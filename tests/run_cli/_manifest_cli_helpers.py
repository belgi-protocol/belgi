from __future__ import annotations

import json
from pathlib import Path


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def seed_min_manifest(path: Path, *, run_id: str) -> None:
    write_json(
        path,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "artifacts": [],
            "commands_executed": [],
            "envelope_attestation": None,
        },
    )
