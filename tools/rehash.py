#!/usr/bin/env python3
"""Unified hasher/rehash entrypoint.

Commands:
- sha256-txt: rehash or check sha256sum-style manifest files
- evidence-manifest: recompute hashes inside EvidenceManifest.json
- protocol-pack: build or verify ProtocolPackManifest.json

Security / determinism posture:
- Repo-root confinement: reject absolute paths, '..', NUL bytes.
- Symlink defense: reject symlink targets and any symlink parent in scope.
- Atomic replace: write temp file, fsync, os.replace.
- Stable JSON serialization: sort keys, LF newlines.
- Fail-closed: any enumerate/read/parse/resolve error => non-zero exit.
"""

# maintainer marker: bk_ycanary_7f3a9c2d

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Sequence

_REPO_ROOT_FOR_IMPORTS = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT_FOR_IMPORTS) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT_FOR_IMPORTS))

from belgi.core.jail import normalize_repo_rel as _normalize_repo_rel
from belgi.core.jail import resolve_repo_rel_path as _resolve_repo_rel_path


class _UserInputError(RuntimeError):
    pass


def _validate_repo_rel(rel: str) -> str:
    try:
        return _normalize_repo_rel(rel, allow_backslashes=True)
    except ValueError as e:
        raise _UserInputError(str(e)) from e


def _resolve_repo_file(repo_root: Path, rel_posix: str) -> Path:
    rel_posix = _validate_repo_rel(rel_posix)
    try:
        return _resolve_repo_rel_path(
            repo_root,
            rel_posix,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
    except ValueError as e:
        raise _UserInputError(str(e)) from e


def _resolve_repo_dir(repo_root: Path, rel_posix: str) -> Path:
    rel_posix = _validate_repo_rel(rel_posix)
    try:
        return _resolve_repo_rel_path(
            repo_root,
            rel_posix,
            must_exist=True,
            must_be_file=False,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
    except ValueError as e:
        raise _UserInputError(str(e)) from e


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp.rehash")
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp.rehash")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def _dump_json(path: Path, obj: Any) -> None:
    _atomic_write_text(
        path,
        json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
    )


def _dump_json_preserve_order(path: Path, obj: Any) -> None:
    _atomic_write_text(
        path,
        json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
    )


def _cmd_protocol_pack(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Build/verify ProtocolPackManifest.json for a protocol pack directory")
    ap.add_argument("--repo", default=".", help="Repo root")
    ap.add_argument(
        "--pack",
        default="belgi/_protocol_packs/v1",
        help="Protocol pack root directory (repo-relative; must contain ProtocolPackManifest.json)",
    )
    ap.add_argument(
        "--pack-name",
        default="",
        help="Override pack_name (default: reuse existing manifest.pack_name if present)",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Validate existing manifest matches current pack bytes without rewriting (exit 2 on mismatch)",
    )
    args = ap.parse_args(argv)

    repo_root = Path(args.repo).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        raise _UserInputError(f"repo root is not a directory: {repo_root}")

    pack_rel = _validate_repo_rel(str(args.pack))
    pack_dir = _resolve_repo_dir(repo_root, pack_rel)

    from belgi.protocol.pack import (
        MANIFEST_FILENAME,
        build_manifest_bytes,
        validate_manifest_bytes,
    )

    manifest_path = pack_dir / MANIFEST_FILENAME
    pack_name = str(args.pack_name or "")
    if not pack_name:
        if manifest_path.exists() and manifest_path.is_file() and not manifest_path.is_symlink():
            try:
                existing = json.loads(manifest_path.read_text(encoding="utf-8", errors="strict"))
                if isinstance(existing, dict) and isinstance(existing.get("pack_name"), str):
                    pack_name = str(existing.get("pack_name") or "")
            except Exception:
                pack_name = ""
    if not pack_name:
        raise _UserInputError("Missing --pack-name and unable to infer pack_name from existing manifest")

    if args.check:
        if not manifest_path.exists():
            print(f"NO-GO: manifest missing: {pack_rel}/{MANIFEST_FILENAME}")
            return 2
        manifest_bytes = manifest_path.read_bytes()
        try:
            validate_manifest_bytes(pack_root=pack_dir, manifest_bytes=manifest_bytes)
        except Exception as e:
            print(f"NO-GO: protocol pack manifest invalid: {pack_rel}/{MANIFEST_FILENAME}: {e}")
            return 2
        print(f"PASS: protocol pack manifest verified: {pack_rel}/{MANIFEST_FILENAME}")
        return 0

    try:
        manifest_bytes = build_manifest_bytes(pack_root=pack_dir, pack_name=pack_name)
    except Exception as e:
        print(f"NO-GO: failed to build manifest: {e}")
        return 2

    _atomic_write_bytes(manifest_path, manifest_bytes)

    try:
        validate_manifest_bytes(pack_root=pack_dir, manifest_bytes=manifest_bytes)
    except Exception as e:
        print(f"NO-GO: validation failed after write: {e}")
        return 2

    parsed = json.loads(manifest_bytes.decode("utf-8", errors="strict"))
    pack_id = parsed.get("pack_id") if isinstance(parsed, dict) else None
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    rel = manifest_path.relative_to(repo_root.resolve()).as_posix()
    print(f"Wrote: {rel}")
    print(f"pack_id: {pack_id}")
    print(f"manifest_sha256: {manifest_sha256}")
    return 0


def _cmd_sha256_txt(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Recompute hashes in a sha256sum-style manifest file")
    ap.add_argument("--repo", default=".", help="Repo root")
    ap.add_argument("--manifest", required=True, help="sha256.txt path (repo-relative)")
    ap.add_argument(
        "--check",
        action="store_true",
        help="Validate sha256.txt matches current bytes without rewriting (exit 2 on mismatch)",
    )
    ap.add_argument(
        "--allow-empty",
        action="store_true",
        help="Allow an empty manifest (default: NO-GO)",
    )
    args = ap.parse_args(argv)

    repo_root = Path(args.repo).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        raise _UserInputError(f"repo root is not a directory: {repo_root}")

    manifest_rel = _validate_repo_rel(str(args.manifest))
    manifest_path = _resolve_repo_file(repo_root, manifest_rel)
    base_dir = manifest_path.parent

    raw_lines = manifest_path.read_text(encoding="utf-8", errors="strict").splitlines()

    out_lines: list[str] = []
    changed = 0
    total = 0

    # sha256sum format: '<64hex>  <path>' (two spaces). Keep parsing deterministic.
    line_re = re.compile(r"^(?P<hash>[0-9a-fA-F]{64})  (?P<name>.+)$")

    for line in raw_lines:
        if not line.strip():
            out_lines.append("")
            continue

        m = line_re.match(line)
        if m is None:
            raise _UserInputError(f"Invalid line (expected '<64hex>  <file>'): {line!r}")

        old_hash = m.group("hash").lower()
        rel_name = _validate_repo_rel(m.group("name"))
        total += 1

        entry_rel = (base_dir.relative_to(repo_root.resolve()) / rel_name).as_posix()
        try:
            target = _resolve_repo_rel_path(
                repo_root,
                entry_rel,
                must_exist=True,
                must_be_file=True,
                allow_backslashes=False,
                forbid_symlinks=True,
            )
        except ValueError as e:
            raise _UserInputError(f"Invalid sha256.txt entry path: {rel_name} ({e})") from e

        new_hash = _sha256_file(target)
        if new_hash != old_hash:
            changed += 1

        out_lines.append(f"{new_hash}  {rel_name}")

    if total == 0 and not args.allow_empty:
        print("NO-GO: sha256 manifest is empty (checked 0 entries)")
        return 2

    rel = manifest_path.relative_to(repo_root.resolve()).as_posix()

    if args.check:
        if changed != 0:
            print(f"NO-GO: sha256 manifest mismatch: {rel} (changed {changed}/{total} entries)")
            return 2
        print(f"PASS: sha256 manifest matches bytes: {rel} ({total} entries)")
        return 0

    _atomic_write_text(manifest_path, "\n".join(out_lines) + "\n")

    print(f"Rehashed: {rel} (changed {changed}/{total} entries)")
    return 0


def _cmd_evidence_manifest(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Recompute sha256(bytes) hashes inside an EvidenceManifest.json")
    ap.add_argument("--repo", default=".", help="Repo root")
    ap.add_argument("--manifest", required=True, help="EvidenceManifest.json path (repo-relative)")
    ap.add_argument(
        "--allow-empty",
        action="store_true",
        help="Allow a manifest with zero hash targets (default: NO-GO)",
    )
    args = ap.parse_args(argv)

    repo_root = Path(args.repo).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        raise _UserInputError(f"repo root is not a directory: {repo_root}")

    em_rel = _validate_repo_rel(str(args.manifest))
    em_path = _resolve_repo_file(repo_root, em_rel)

    doc = _load_json(em_path)
    if not isinstance(doc, dict):
        print("NO-GO: EvidenceManifest must be a JSON object", file=sys.stderr)
        raise SystemExit(2)

    changed = False
    checked = 0

    artifacts = doc.get("artifacts")
    if isinstance(artifacts, list):
        for a in artifacts:
            if not isinstance(a, dict):
                continue
            storage_ref = a.get("storage_ref")
            if not isinstance(storage_ref, str) or not storage_ref.strip():
                continue
            p = _resolve_repo_file(repo_root, storage_ref)
            checked += 1
            new_hash = _sha256_file(p)
            old_hash = a.get("hash")
            if old_hash != new_hash:
                a["hash"] = new_hash
                changed = True

    env_att = doc.get("envelope_attestation")
    if isinstance(env_att, dict):
        storage_ref = env_att.get("storage_ref")
        if isinstance(storage_ref, str) and storage_ref.strip():
            p = _resolve_repo_file(repo_root, storage_ref)
            checked += 1
            new_hash = _sha256_file(p)
            old_hash = env_att.get("hash")
            if old_hash != new_hash:
                env_att["hash"] = new_hash
                changed = True

    if checked == 0 and not args.allow_empty:
        print(f"NO-GO: no hash targets found in EvidenceManifest: {em_rel} (checked 0)")
        return 2

    if changed:
        _dump_json(em_path, doc)
        print(f"Updated hashes: {em_path.relative_to(repo_root.resolve()).as_posix()}")
    else:
        print(f"No changes needed: {em_path.relative_to(repo_root.resolve()).as_posix()}")

    return 0


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Unified rehash entrypoint")
    ap.add_argument(
        "cmd",
        choices=[
            "sha256-txt",
            "evidence-manifest",
            "protocol-pack",
        ],
        help="Subcommand",
    )
    ap.add_argument("args", nargs=argparse.REMAINDER, help="Subcommand args (optional leading '--' accepted)")
    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: list[str] | None = None) -> int:
    try:
        ns = _parse_args(argv)
        rest = [a for a in ns.args if a != "--"]

        if ns.cmd == "sha256-txt":
            return _cmd_sha256_txt(rest)
        if ns.cmd == "evidence-manifest":
            return _cmd_evidence_manifest(rest)
        if ns.cmd == "protocol-pack":
            return _cmd_protocol_pack(rest)

        raise _UserInputError(f"Unknown command: {ns.cmd}")
    except _UserInputError as e:
        print(f"NO-GO: {e}")
        return 2
    except json.JSONDecodeError as e:
        print(f"NO-GO: JSON parse error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
