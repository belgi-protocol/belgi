#!/usr/bin/env python3
"""Locate the latest BELGI run attempt and print triage pointers."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RC_GO = 0
RC_NO_GO = 2

TS_KEYS = {
    "timestamp",
    "generated_at",
    "created_at",
    "started_at",
    "finished_at",
    "evaluated_at",
    "completed_at",
    "updated_at",
}


def _parse_timestamp(raw: Any) -> float | None:
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc).timestamp()


def _extract_timestamp(node: Any) -> float | None:
    if isinstance(node, dict):
        for key in (
            "generated_at",
            "timestamp",
            "created_at",
            "evaluated_at",
            "started_at",
            "finished_at",
            "completed_at",
            "updated_at",
        ):
            if key in node:
                ts = _parse_timestamp(node.get(key))
                if ts is not None:
                    return ts
        for key, value in node.items():
            if str(key).strip().lower() in TS_KEYS:
                ts = _parse_timestamp(value)
                if ts is not None:
                    return ts
        for value in node.values():
            ts = _extract_timestamp(value)
            if ts is not None:
                return ts
    elif isinstance(node, list):
        for value in node:
            ts = _extract_timestamp(value)
            if ts is not None:
                return ts
    return None


def _safe_json(path: Path) -> dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _search_dirs(repo_root: Path) -> list[Path]:
    dirs: list[Path] = [repo_root / ".belgi" / "runs"]
    for child in sorted(repo_root.iterdir(), key=lambda p: p.name):
        if child.is_dir() and child.name.startswith(".belgi") and child.name != ".belgi":
            dirs.append(child / "runs")
    unique: list[Path] = []
    seen: set[str] = set()
    for path in dirs:
        key = path.as_posix()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _discover_summary_paths(search_dirs: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for runs_dir in search_dirs:
        if not runs_dir.is_dir():
            continue
        for summary_path in sorted(runs_dir.glob("*/*/run.summary.json")):
            if summary_path.is_file():
                paths.append(summary_path.resolve())
    return paths


def _artifact_paths(repo_root: Path, summary: dict[str, Any]) -> list[Path]:
    out: list[Path] = []
    artifacts = summary.get("artifacts")
    if not isinstance(artifacts, list):
        return out
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        rel = item.get("path")
        if not isinstance(rel, str) or not rel.strip():
            continue
        out.append((repo_root / rel).resolve())
    return out


def _pick_latest_summary(repo_root: Path, summaries: list[Path]) -> tuple[Path, dict[str, Any], str]:
    picks: list[tuple[float, str, Path, dict[str, Any], str]] = []
    for summary_path in summaries:
        summary_obj = _safe_json(summary_path)
        metadata_ts = _extract_timestamp(summary_obj)
        if metadata_ts is not None:
            sort_ts = metadata_ts
            source = "metadata"
        else:
            sort_ts = summary_path.stat().st_mtime
            source = "mtime"
        picks.append((sort_ts, summary_path.as_posix(), summary_path, summary_obj, source))

    picks.sort(key=lambda row: (row[0], row[1]), reverse=True)
    _ts, _stable, summary_path, summary_obj, source = picks[0]
    return summary_path, summary_obj, source


def _print_no_runs(searched: list[Path]) -> int:
    print("[belgi latest-run] NO-GO: no BELGI runs found.")
    print("[belgi latest-run] searched directories:")
    for path in searched:
        print(f"  - {path}")
    return RC_NO_GO


def cmd_main(repo_root: Path) -> int:
    searched = _search_dirs(repo_root)
    summaries = _discover_summary_paths(searched)
    if not summaries:
        return _print_no_runs(searched)

    summary_path, summary_obj, selection_source = _pick_latest_summary(repo_root, summaries)
    attempt_dir = summary_path.parent
    run_key = summary_obj.get("run_key")
    attempt_id = summary_obj.get("attempt_id")
    if isinstance(run_key, str) and run_key and isinstance(attempt_id, str) and attempt_id:
        run_label = f"{run_key}/{attempt_id}"
    else:
        run_label = f"{attempt_dir.parent.name}/{attempt_dir.name}"

    machine_candidates: list[Path] = [
        attempt_dir / "machine.json",
        attempt_dir / "machine_result.json",
        attempt_dir / "BELGI_RESULT.json",
        attempt_dir / "repo" / "out" / "machine.json",
    ]
    for artifact_path in _artifact_paths(repo_root, summary_obj):
        name = artifact_path.name.lower()
        if name.endswith(".json") and "machine" in name:
            machine_candidates.append(artifact_path)

    machine_path: Path | None = None
    for candidate in machine_candidates:
        if candidate.is_file():
            machine_path = candidate
            break

    gate_candidates = [
        attempt_dir / "repo" / "out" / "GateVerdict.Q.json",
        attempt_dir / "repo" / "out" / "GateVerdict.R.json",
        attempt_dir / "repo" / "out" / "GateVerdict.S.json",
        attempt_dir / "repo" / "out" / "verify_report.R.json",
        attempt_dir / "repo" / "out" / "GateVerdict_Q.json",
        attempt_dir / "repo" / "out" / "GateVerdict_R.json",
        attempt_dir / "repo" / "out" / "GateVerdict_S.json",
    ]
    gate_paths = [path for path in gate_candidates if path.is_file()]

    print(f"latest_run_root: {attempt_dir}")
    print(f"latest_run_key_attempt: {run_label}")
    print(f"selection_source: {selection_source}")
    print(f"run.summary.json: {summary_path}")
    if machine_path is not None:
        print(f"machine_json: {machine_path}")
    else:
        print("machine_json: (not found)")

    if gate_paths:
        print("gate_outputs:")
        for path in gate_paths:
            print(f"  - {path}")
    else:
        print("gate_outputs: (not found)")

    print("triage_pointers:")
    print(f"  - python -m belgi.cli verify --repo \"{repo_root}\" --in \"{summary_path}\"")
    print(f"  - cat \"{summary_path}\"")
    if gate_paths:
        print(f"  - cat \"{gate_paths[-1]}\"")
    else:
        print(f"  - ls -1 \"{attempt_dir}\"")
    return RC_GO


def main() -> int:
    parser = argparse.ArgumentParser(description="Print the latest BELGI run attempt paths.")
    parser.add_argument("--root", default=".", help="Repository root override (default: current directory).")
    args = parser.parse_args()

    repo_root = Path(str(args.root)).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        print(f"[belgi latest-run] ERROR: invalid --root directory: {repo_root}")
        return RC_NO_GO

    return cmd_main(repo_root)


if __name__ == "__main__":
    raise SystemExit(main())
