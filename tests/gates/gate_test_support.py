from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_module(module: str, args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


def _read_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(obj, dict)
    return obj


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _setup_fake_repo_with_pack(tmp_path: Path, builtin_pack_root: Path) -> Path:
    pack_root = tmp_path / "protocol_pack"
    shutil.copytree(builtin_pack_root, pack_root, dirs_exist_ok=True)
    return pack_root


def _tamper_locked_spec_pack_id(locked_path: Path, new_pack_id: str) -> None:
    data = json.loads(locked_path.read_text(encoding="utf-8", errors="strict"))
    data["protocol_pack"]["pack_id"] = new_pack_id
    locked_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8", errors="strict")


def _sync_locked_spec_protocol_identity(locked_path: Path, protocol_manifest_path: Path) -> None:
    data = json.loads(locked_path.read_text(encoding="utf-8", errors="strict"))
    manifest = json.loads(protocol_manifest_path.read_text(encoding="utf-8", errors="strict"))
    data["protocol_pack"]["pack_id"] = manifest["pack_id"]
    data["protocol_pack"]["manifest_sha256"] = _sha256_hex(protocol_manifest_path.read_bytes())
    data["protocol_pack"]["pack_name"] = manifest["pack_name"]
    locked_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _remove_locked_spec_protocol_pack(locked_path: Path) -> None:
    data = json.loads(locked_path.read_text(encoding="utf-8", errors="strict"))
    del data["protocol_pack"]
    locked_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8", errors="strict")


__all__ = [
    "REPO_ROOT",
    "_read_json",
    "_remove_locked_spec_protocol_pack",
    "_run_module",
    "_setup_fake_repo_with_pack",
    "_sha256_hex",
    "_sync_locked_spec_protocol_identity",
    "_tamper_locked_spec_pack_id",
]
