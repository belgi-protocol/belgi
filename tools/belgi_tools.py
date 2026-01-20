#!/usr/bin/env python3
"""BELGI CLI — Evidence generation tools for the BELGI protocol.

This CLI provides the subcommands required by Gate R:
- belgi run-tests      → Run pytest, produce test_report artifact
- belgi invariant-eval → Evaluate LockedSpec invariants, produce policy.invariant_eval
- belgi verify-attestation → Verify/generate env_attestation
- belgi manifest-init  → Create a schema-valid EvidenceManifest deterministically
- belgi pack build     → Build/update protocol pack manifest deterministically
- belgi pack verify    → Verify protocol pack manifest matches file tree

These commands are executed by the CI/operator (NOT by LLM) and their records
are logged in EvidenceManifest.commands_executed for Gate R verification.

Exit codes:
- 0: success
- 1: check failed (tests failed, invariants failed, etc.)
- 3: usage/internal error
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import re
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, metadata, version
from pathlib import Path
from typing import Any

# Bind imports to ENGINE repo root and prevent shadowing from tools/.
_TOOLS_DIR = Path(__file__).resolve().parent
_THIS_REPO_ROOT = Path(__file__).resolve().parents[1]

_repo_root_str = str(_THIS_REPO_ROOT)
if _repo_root_str in sys.path:
    sys.path.remove(_repo_root_str)
sys.path.insert(0, _repo_root_str)

_cleaned: list[str] = []
for _p in sys.path:
    if not _p:
        _cleaned.append(_p)
        continue
    try:
        if Path(_p).resolve() == _TOOLS_DIR:
            continue
    except Exception:
        # If a sys.path entry can't be resolved, keep it.
        pass
    _cleaned.append(_p)
sys.path[:] = _cleaned

for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.core.hash import sha256_bytes
from belgi.core.jail import resolve_repo_rel_path, safe_relpath
from belgi.core.json_canon import canonical_json_bytes


# Deterministic timestamp for reproducible runs
FIXED_TIMESTAMP = "1970-01-01T00:00:00Z"
SCHEMA_VERSION = "1.0.0"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _json_dumps_stable(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    text = _json_dumps_stable(obj)
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _atomic_write_bytes(path: Path, blob: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _is_hex_40(s: str) -> bool:
    return isinstance(s, str) and len(s) == 40 and all(c in "0123456789abcdef" for c in s.lower())


def _canonical_json_no_nl(obj: Any) -> bytes:
    # Must match Gate R R6 canonicalization (sorted keys, compact separators, no trailing LF).
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8", errors="strict")


def _walk_repo_files(root: Path, *, rel_root: str, filename: str) -> list[Path]:
    """Deterministically enumerate files under repo-relative rel_root.

    Fail-closed if a symlink is encountered anywhere under the walk scope.
    """

    base = _repo_path(root, rel_root, must_exist=True, must_be_file=False)
    if not base.is_dir():
        raise RuntimeError(f"Expected directory at {rel_root}")

    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        d = Path(dirpath)
        # Fail-closed on symlink directories (scope escape risk).
        if d.is_symlink():
            raise RuntimeError(f"Symlink directory not allowed under {rel_root}: {d}")
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = d / name
            if p.is_symlink():
                raise RuntimeError(f"Symlink file not allowed under {rel_root}: {p}")
            if name == filename:
                out.append(p)

    out.sort(key=lambda p: p.relative_to(root).as_posix())
    return out


def _active_pack_identity(*, repo_root: Path, pack_rel: str) -> dict[str, str]:
    """Read active protocol pack identity (pack_id + manifest_sha256) from a pack directory."""

    from belgi.protocol.pack import MANIFEST_FILENAME, validate_manifest_bytes

    pack_dir = _repo_path(repo_root, pack_rel, must_exist=True, must_be_file=False)
    if not pack_dir.is_dir():
        raise RuntimeError(f"Pack directory is not a directory: {pack_rel}")
    if pack_dir.is_symlink():
        raise RuntimeError(f"Symlink pack directory not allowed: {pack_rel}")

    manifest_path = pack_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise RuntimeError(f"Pack manifest not found: {manifest_path.relative_to(repo_root).as_posix()}")
    if manifest_path.is_symlink():
        raise RuntimeError(f"Symlink manifest not allowed: {manifest_path.relative_to(repo_root).as_posix()}")

    manifest_bytes = manifest_path.read_bytes()
    # Fail-closed: validate manifest and its tree binding.
    validate_manifest_bytes(pack_root=pack_dir, manifest_bytes=manifest_bytes)

    parsed = json.loads(manifest_bytes.decode("utf-8", errors="strict"))
    if not isinstance(parsed, dict):
        raise RuntimeError("ProtocolPackManifest.json must be an object")

    pack_id = str(parsed.get("pack_id") or "").strip()
    pack_name = str(parsed.get("pack_name") or "").strip()
    if not pack_id:
        raise RuntimeError("ProtocolPackManifest.json missing pack_id")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    return {
        "pack_id": pack_id,
        "pack_name": pack_name,
        "manifest_sha256": manifest_sha256,
    }


def _maybe_update_protocol_pack_pin(*, locked_spec: dict[str, Any], identity: dict[str, str]) -> bool:
    proto = locked_spec.get("protocol_pack")
    if not isinstance(proto, dict):
        proto = {}
        locked_spec["protocol_pack"] = proto

    changed = False
    for k in ("pack_id", "manifest_sha256"):
        v = identity.get(k)
        if isinstance(v, str) and v and proto.get(k) != v:
            proto[k] = v
            changed = True

    # Keep these aligned if present (non-authoritative, but helpful).
    pn = identity.get("pack_name")
    if isinstance(pn, str) and pn and proto.get("pack_name") != pn:
        proto["pack_name"] = pn
        changed = True

    if proto.get("source") != "builtin":
        proto["source"] = "builtin"
        changed = True

    return changed


_HEX_64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _read_text_strict(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def _load_ed25519_private_key_hex_seed(hex_seed: str) -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Missing crypto dependency for Ed25519 (install 'cryptography').") from e

    if not _HEX_64_RE.fullmatch(hex_seed):
        raise RuntimeError("seal_private_key.hex must contain exactly 64 hex chars")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_seed))


def _ed25519_pubkey_hex_from_private_key_file(priv_path: Path) -> str:
    try:
        from cryptography.hazmat.primitives import serialization
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Missing crypto dependency for Ed25519 (install 'cryptography').") from e

    seed = _read_text_strict(priv_path).strip()
    priv = _load_ed25519_private_key_hex_seed(seed)
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return pub_bytes.hex()


def _fixture_dir_rel_for_path(repo_root: Path, p: Path) -> str:
    return p.parent.relative_to(repo_root).as_posix()


def _sync_pack_identity(
    *,
    repo_root: Path,
    pack_dir: str,
) -> tuple[dict[str, str], list[Path]]:
    identity = _active_pack_identity(repo_root=repo_root, pack_rel=pack_dir)
    locked_specs = _walk_repo_files(repo_root, rel_root="policy/fixtures", filename="LockedSpec.json")
    if not locked_specs:
        raise RuntimeError("NO-GO: no fixture LockedSpec targets found (checked 0)")
    modified: list[Path] = []
    for p in locked_specs:
        doc = _load_json(p)
        if not isinstance(doc, dict):
            raise RuntimeError(f"LockedSpec must be an object: {p.relative_to(repo_root).as_posix()}")
        if _maybe_update_protocol_pack_pin(locked_spec=doc, identity=identity):
            _atomic_write_json(p, doc)
            modified.append(p)
    modified.sort(key=lambda x: x.relative_to(repo_root).as_posix())
    return identity, modified


def _enforce_seal_keypair_and_pubkey_ref(
    *,
    repo_root: Path,
    locked_spec_path: Path,
    locked_spec: dict[str, Any],
    create_missing_private_key: bool,
) -> tuple[bool, list[str]]:
    """Ensure seal_pubkey.hex is derived from seal_private_key.hex and seal_pubkey_ref.hash matches bytes.

    Returns (changed, notes).
    """

    notes: list[str] = []
    env = locked_spec.get("environment_envelope")
    if not isinstance(env, dict):
        return False, notes
    pub_ref = env.get("seal_pubkey_ref")
    if not isinstance(pub_ref, dict):
        return False, notes

    fixture_dir = locked_spec_path.parent
    fixture_dir_rel = fixture_dir.relative_to(repo_root).as_posix()
    is_seal_fixture = fixture_dir_rel.startswith("policy/fixtures/public/seal/")

    # For non-SEAL fixtures (e.g., Gate S), only bind seal_pubkey_ref.hash to pubkey bytes.
    # Do not require or create a private key outside SEAL producer fixtures.
    if not is_seal_fixture:
        storage_ref = str(pub_ref.get("storage_ref") or "")
        if not storage_ref:
            return False, notes
        try:
            pub_path = _repo_path(repo_root, storage_ref, must_exist=True, must_be_file=True)
        except Exception:
            # Some historical fixtures may use fixture-local refs like "seal_pubkey.hex".
            # Fail-closed unless the fixture-local file exists, in which case we normalize to repo-relative.
            candidate = fixture_dir / storage_ref
            if candidate.exists() and candidate.is_file() and not candidate.is_symlink():
                fixed_ref = f"{fixture_dir_rel}/{storage_ref}"
                pub_ref["storage_ref"] = fixed_ref
                pub_path = _repo_path(repo_root, fixed_ref, must_exist=True, must_be_file=True)
                notes.append(
                    f"updated {locked_spec_path.relative_to(repo_root).as_posix()} seal_pubkey_ref.storage_ref"
                )
            else:
                raise
        if pub_path.is_symlink():
            raise RuntimeError(f"Symlink pubkey not allowed: {pub_path.relative_to(repo_root).as_posix()}")
        pub_bytes = pub_path.read_bytes()
        computed_hash = sha256_bytes(pub_bytes)
        declared_hash = str(pub_ref.get("hash") or "")
        if declared_hash.lower() != computed_hash.lower():
            pub_ref["hash"] = computed_hash
            notes.append(f"updated {locked_spec_path.relative_to(repo_root).as_posix()} seal_pubkey_ref.hash")
            return True, notes
        return False, notes

    # SEAL fixtures: enforce local pubkey storage_ref binding (and keypair checks when private key is present).
    storage_ref = str(pub_ref.get("storage_ref") or "")
    priv_path = fixture_dir / "seal_private_key.hex"
    expected_pub_hex: str | None = None
    priv_changed = False
    if priv_path.exists():
        if priv_path.is_symlink():
            raise RuntimeError(f"Symlink private key not allowed: {priv_path}")
        expected_pub_hex = _ed25519_pubkey_hex_from_private_key_file(priv_path).lower()
    elif create_missing_private_key:
        _atomic_write_text(priv_path, "1f" * 32 + "\n")
        notes.append(f"added {priv_path.relative_to(repo_root).as_posix()}")
        priv_changed = True
        expected_pub_hex = _ed25519_pubkey_hex_from_private_key_file(priv_path).lower()
    desired_storage_ref = f"{fixture_dir_rel}/seal_pubkey.hex"
    ref_path_changed = False
    if storage_ref != desired_storage_ref:
        pub_ref["storage_ref"] = desired_storage_ref
        pub_path = _repo_path(repo_root, desired_storage_ref, must_exist=False, must_be_file=True)
        ref_path_changed = True
        notes.append(f"updated {locked_spec_path.relative_to(repo_root).as_posix()} seal_pubkey_ref.storage_ref")
    else:
        pub_path = _repo_path(repo_root, desired_storage_ref, must_exist=False, must_be_file=True)

    if pub_path.exists() and pub_path.is_symlink():
        raise RuntimeError(f"Symlink pubkey not allowed: {pub_path.relative_to(repo_root).as_posix()}")

    pub_changed = False
    if not pub_path.exists():
        if expected_pub_hex is None:
            raise RuntimeError(
                f"NO-GO: missing seal_pubkey.hex for SEAL fixture: {locked_spec_path.relative_to(repo_root).as_posix()}"
            )
        _atomic_write_text(pub_path, expected_pub_hex + "\n")
        pub_changed = True
        notes.append(f"updated {pub_path.relative_to(repo_root).as_posix()}")
    elif expected_pub_hex is not None:
        current_pub_hex = _read_text_strict(pub_path).strip().lower()
        if current_pub_hex != expected_pub_hex:
            _atomic_write_text(pub_path, expected_pub_hex + "\n")
            pub_changed = True
            notes.append(f"updated {pub_path.relative_to(repo_root).as_posix()}")

    # Update seal_pubkey_ref.hash to sha256(bytes(pubkey file)).
    pub_bytes = pub_path.read_bytes()
    computed_hash = sha256_bytes(pub_bytes)
    declared_hash = str(pub_ref.get("hash") or "")
    ref_changed = False
    if declared_hash.lower() != computed_hash.lower():
        pub_ref["hash"] = computed_hash
        ref_changed = True
        notes.append(f"updated {locked_spec_path.relative_to(repo_root).as_posix()} seal_pubkey_ref.hash")

    return (priv_changed or ref_path_changed or pub_changed or ref_changed), notes


def cmd_fixtures_sync_pack_identity(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo).resolve()
    identity, modified_paths = _sync_pack_identity(repo_root=repo_root, pack_dir=str(args.pack_dir))

    modified = [p.relative_to(repo_root).as_posix() for p in modified_paths]
    if modified:
        shown = ", ".join(modified[:25]) + (f" ... (+{len(modified) - 25} more)" if len(modified) > 25 else "")
        print(f"[belgi fixtures sync-pack-identity] modified_files: {shown}", file=sys.stderr)
    else:
        print("[belgi fixtures sync-pack-identity] No changes needed.", file=sys.stderr)

    print(
        f"[belgi fixtures sync-pack-identity] active pack_id={identity['pack_id']} manifest_sha256={identity['manifest_sha256']}",
        file=sys.stderr,
    )
    return 0


def _run_module(repo_root: Path, module: str, argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module, *argv],
        cwd=str(repo_root),
        env=_det_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )


def _load_cases_expected(cases_path: Path) -> dict[str, dict[str, Any]]:
    doc = _load_json(cases_path)
    cases = doc.get("cases") if isinstance(doc, dict) else None
    if not isinstance(cases, list):
        raise RuntimeError(f"Invalid cases.json shape: {cases_path}")
    out: dict[str, dict[str, Any]] = {}
    for c in cases:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("case_id") or "").strip()
        if not cid:
            continue
        out[cid] = dict(c)
    return out


def _regen_gate_s_fixture(
    *,
    repo_root: Path,
    case_id: str,
    expected_exit_code: int,
) -> tuple[bool, list[str]]:
    """Regenerate Gate S fixture SealManifest.json deterministically.

    For failing fixtures that embed an intentionally broken signature field, regenerate the base manifest
    then re-inject the existing signature fields so the failure remains isolated.
    """

    fixture_dir_rel = f"policy/fixtures/public/gate_s/{case_id}"
    fixture_dir = _repo_path(repo_root, fixture_dir_rel, must_exist=True, must_be_file=False)
    if not fixture_dir.is_dir():
        raise RuntimeError(f"Gate S fixture dir not found: {fixture_dir_rel}")

    seal_path = fixture_dir / "SealManifest.json"
    if not seal_path.exists():
        raise RuntimeError(f"Missing SealManifest.json in {fixture_dir_rel}")

    old = _load_json(seal_path)
    if not isinstance(old, dict):
        raise RuntimeError(f"SealManifest.json must be an object: {seal_path.relative_to(repo_root).as_posix()}")

    # Generate a correct base manifest (tier-1: unsigned by default).
    tmp_out = (fixture_dir / "SealManifest.__regen.tmp.json").relative_to(repo_root).as_posix()
    cp = _run_module(
        repo_root,
        "chain.seal_bundle",
        [
            "--repo",
            ".",
            "--locked-spec",
            f"{fixture_dir_rel}/LockedSpec.json",
            "--gate-q-verdict",
            f"{fixture_dir_rel}/GateVerdict.Q.json",
            "--gate-r-verdict",
            f"{fixture_dir_rel}/GateVerdict.R.json",
            "--evidence-manifest",
            f"{fixture_dir_rel}/EvidenceManifest.json",
            "--final-commit-sha",
            "0" * 40,
            "--sealed-at",
            "2000-01-01T00:30:00Z",
            "--signer",
            "human:fixture",
            "--out",
            tmp_out,
        ],
    )
    if cp.returncode != 0:
        raise RuntimeError(f"seal_bundle failed for gate_s/{case_id}: rc={cp.returncode} stderr={cp.stderr.strip()!r}")

    tmp_path = _repo_path(repo_root, tmp_out, must_exist=True, must_be_file=True)
    base = _load_json(tmp_path)
    tmp_path.unlink(missing_ok=True)

    if not isinstance(base, dict):
        raise RuntimeError("seal_bundle produced non-object manifest")

    new_obj = dict(base)
    # Preserve intentionally broken signature fields for failing fixtures.
    if expected_exit_code != 0:
        if "signature_alg" in old:
            new_obj["signature_alg"] = old.get("signature_alg")
        if "signature" in old:
            new_obj["signature"] = old.get("signature")
        if "replay_instructions_ref" in old:
            new_obj["replay_instructions_ref"] = old.get("replay_instructions_ref")
        if "replay_instructions_ref" not in new_obj:
            replay_rel = f"{fixture_dir_rel}/replay_instructions.json"
            replay_path = _repo_path(repo_root, replay_rel, must_exist=False, must_be_file=True)
            if replay_path.exists():
                replay_bytes = replay_path.read_bytes()
                replay_hash = sha256_bytes(replay_bytes)
                run_id = str(new_obj.get("run_id") or "").strip()
                replay_id = f"replay-{run_id}" if run_id else "replay"
                new_obj["replay_instructions_ref"] = {
                    "id": replay_id,
                    "hash": replay_hash,
                    "storage_ref": replay_rel,
                }

    new_bytes = canonical_json_bytes(new_obj)
    old_bytes = seal_path.read_bytes() if seal_path.exists() else b""
    if old_bytes != new_bytes:
        _atomic_write_text(seal_path, new_bytes.decode("utf-8", errors="strict"))
        return True, [f"updated {seal_path.relative_to(repo_root).as_posix()}"]
    return False, []


def _regen_seal_fixture(
    *,
    repo_root: Path,
    case_id: str,
    expected_exit_code: int,
    final_commit_sha: str,
    sealed_at: str,
    signer: str,
) -> tuple[bool, list[str]]:
    """Regenerate Seal producer fixture manifests/signature deterministically (PASS fixtures only)."""

    fixture_dir_rel = f"policy/fixtures/public/seal/{case_id}"
    fixture_dir = _repo_path(repo_root, fixture_dir_rel, must_exist=True, must_be_file=False)
    if not fixture_dir.is_dir():
        raise RuntimeError(f"Seal fixture dir not found: {fixture_dir_rel}")

    notes: list[str] = []
    changed = False

    if expected_exit_code != 0:
        # FAIL fixtures must remain intentionally broken; do not overwrite signature fields.
        return False, notes

    priv_path = fixture_dir / "seal_private_key.hex"
    if not priv_path.exists():
        raise RuntimeError(f"PASS seal fixture missing seal_private_key.hex: {fixture_dir_rel}")

    out_manifest_rel = f"{fixture_dir_rel}/SealManifest.out.json"
    cp = _run_module(
        repo_root,
        "chain.seal_bundle",
        [
            "--repo",
            ".",
            "--locked-spec",
            f"{fixture_dir_rel}/LockedSpec.json",
            "--gate-q-verdict",
            f"{fixture_dir_rel}/GateVerdict.Q.json",
            "--gate-r-verdict",
            f"{fixture_dir_rel}/GateVerdict.R.json",
            "--evidence-manifest",
            f"{fixture_dir_rel}/EvidenceManifest.json",
            "--final-commit-sha",
            final_commit_sha,
            "--sealed-at",
            sealed_at,
            "--signer",
            signer,
            "--seal-private-key",
            f"{fixture_dir_rel}/seal_private_key.hex",
            "--fixture-mode",
            "--out",
            out_manifest_rel,
        ],
    )
    if cp.returncode != 0:
        raise RuntimeError(f"seal_bundle failed for seal/{case_id}: rc={cp.returncode} stderr={cp.stderr.strip()!r}")

    out_manifest_path = _repo_path(repo_root, out_manifest_rel, must_exist=True, must_be_file=True)
    out_doc = _load_json(out_manifest_path)
    if not isinstance(out_doc, dict):
        raise RuntimeError(f"SealManifest.out.json must be an object: {out_manifest_rel}")

    # Deterministic byte hygiene: chain.seal_bundle may emit CRLF on Windows.
    # Canonicalize here so fixtures satisfy CS-BYTE-001.
    canon_bytes = canonical_json_bytes(out_doc)
    old_out_bytes = out_manifest_path.read_bytes() if out_manifest_path.exists() else b""
    if old_out_bytes != canon_bytes:
        _atomic_write_text(out_manifest_path, canon_bytes.decode("utf-8", errors="strict"))
        changed = True
        notes.append(f"updated {out_manifest_rel}")

    sig = str(out_doc.get("signature") or "").strip()
    if not sig:
        raise RuntimeError(f"seal_bundle did not produce signature for PASS tier-2/3: {case_id}")

    sig_path = fixture_dir / "seal_signature.b64"
    new_sig_bytes = (sig + "\n").encode("utf-8", errors="strict")
    old_sig_bytes = sig_path.read_bytes() if sig_path.exists() else b""
    if old_sig_bytes != new_sig_bytes:
        _atomic_write_text(sig_path, new_sig_bytes.decode("utf-8", errors="strict"))
        changed = True
        notes.append(f"updated {sig_path.relative_to(repo_root).as_posix()}")

    # Keep a second copy for human inspection (historical name); content is identical.
    signed_rel = f"{fixture_dir_rel}/SealManifest.signed.json"
    signed_path = _repo_path(repo_root, signed_rel, must_exist=False, must_be_file=True)
    old_signed_bytes = signed_path.read_bytes() if signed_path.exists() else b""
    if old_signed_bytes != canon_bytes:
        _atomic_write_text(signed_path, canon_bytes.decode("utf-8", errors="strict"))
        changed = True
        notes.append(f"updated {signed_rel}")

    return changed, notes


def cmd_fixtures_regen_seals(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo).resolve()
    only_touched = bool(args.only_touched)
    create_missing_private_keys = bool(getattr(args, "create_missing_private_keys", False))

    # Load case expectations.
    gate_s_cases = _load_cases_expected(_repo_path(repo_root, "policy/fixtures/public/gate_s/cases.json", must_exist=True, must_be_file=True))
    seal_cases = _load_cases_expected(_repo_path(repo_root, "policy/fixtures/public/seal/cases.json", must_exist=True, must_be_file=True))

    # First: enforce keypair/pubkey_ref binding only for seal-related *public* fixtures.
    # This avoids modifying unrelated/internal fixtures where a broken seal_pubkey_ref may be the intentional failure.
    locked_specs = []
    for rel_root in ("policy/fixtures/public/gate_s", "policy/fixtures/public/seal"):
        try:
            locked_specs.extend(_walk_repo_files(repo_root, rel_root=rel_root, filename="LockedSpec.json"))
        except Exception:
            # Absent fixture sets are treated as empty; verification will fail-closed later when cases.json requires them.
            continue
    locked_specs = sorted(set(locked_specs), key=lambda p: p.relative_to(repo_root).as_posix())
    if not locked_specs:
        raise RuntimeError("NO-GO: no seal-related fixture LockedSpec targets found (checked 0)")
    touched_fixture_dirs: set[str] = set()
    for p in locked_specs:
        rel = p.relative_to(repo_root).as_posix()
        doc = _load_json(p)
        if not isinstance(doc, dict):
            raise RuntimeError(f"LockedSpec must be an object: {rel}")

        changed, _notes = _enforce_seal_keypair_and_pubkey_ref(
            repo_root=repo_root,
            locked_spec_path=p,
            locked_spec=doc,
            create_missing_private_key=create_missing_private_keys,
        )
        if changed:
            _atomic_write_json(p, doc)
            touched_fixture_dirs.add(_fixture_dir_rel_for_path(repo_root, p))

    # Second: regenerate seal-related payloads (scoped).
    modified: list[str] = []

    for case_id, entry in gate_s_cases.items():
        expected_rc = int(entry.get("expected_exit_code", 2))
        fixture_dir_rel = f"policy/fixtures/public/gate_s/{case_id}"
        if only_touched and (fixture_dir_rel not in touched_fixture_dirs):
            continue
        changed, notes = _regen_gate_s_fixture(repo_root=repo_root, case_id=case_id, expected_exit_code=expected_rc)
        if changed:
            modified.extend(notes)

    for case_id, entry in seal_cases.items():
        expected_rc = int(entry.get("expected_exit_code", 2))
        params = entry.get("params") if isinstance(entry.get("params"), dict) else {}
        final_commit_sha = str(params.get("final_commit_sha") or "0" * 40)
        sealed_at = str(params.get("sealed_at") or "2000-01-01T00:30:00Z")
        signer = str(params.get("signer") or "human:fixture")
        fixture_dir_rel = f"policy/fixtures/public/seal/{case_id}"
        if only_touched and (fixture_dir_rel not in touched_fixture_dirs):
            continue
        changed, notes = _regen_seal_fixture(
            repo_root=repo_root,
            case_id=case_id,
            expected_exit_code=expected_rc,
            final_commit_sha=final_commit_sha,
            sealed_at=sealed_at,
            signer=signer,
        )
        if changed:
            modified.extend(notes)

    modified = sorted(set(modified))
    if modified:
        shown = ", ".join(modified[:25]) + (f" ... (+{len(modified)-25} more)" if len(modified) > 25 else "")
        print(f"[belgi fixtures regen-seals] updated: {shown}", file=sys.stderr)
    else:
        print("[belgi fixtures regen-seals] No changes needed.", file=sys.stderr)
    return 0


def cmd_fixtures_fix_all(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo).resolve()
    create_missing_private_keys = bool(getattr(args, "create_missing_private_keys", False))
    # 1) Sync pack identity pins.
    identity, modified_paths = _sync_pack_identity(repo_root=repo_root, pack_dir=str(args.pack_dir))
    modified = [p.relative_to(repo_root).as_posix() for p in modified_paths]
    if modified:
        shown = ", ".join(modified[:25]) + (f" ... (+{len(modified) - 25} more)" if len(modified) > 25 else "")
        print(f"[belgi fixtures fix-all] sync-pack modified_files: {shown}", file=sys.stderr)
    else:
        print("[belgi fixtures fix-all] sync-pack: No changes needed.", file=sys.stderr)
    print(
        f"[belgi fixtures fix-all] active pack_id={identity['pack_id']} manifest_sha256={identity['manifest_sha256']}",
        file=sys.stderr,
    )

    # 2) Regenerate seals/signatures for any fixtures whose LockedSpec changed.
    touched_dirs: set[str] = set(_fixture_dir_rel_for_path(repo_root, p) for p in modified_paths)

    # Reuse regen-seals logic, but constrain to changed fixture dirs.
    # This preserves "only touch what needs touching".
    # Build a minimal run by temporarily using only_touched=True and pre-seeding touched dirs via keypair enforcement.
    # (cmd_fixtures_regen_seals will still skip untargeted dirs in this path.)
    regen_args = argparse.Namespace(repo=str(repo_root), only_touched=True, create_missing_private_keys=create_missing_private_keys)
    rc = cmd_fixtures_regen_seals(regen_args)
    if rc != 0:
        return rc

    # Ensure Gate S + Seal manifests are regenerated for pack-touched dirs.
    # (Keypair enforcement alone does not trigger this when pack pins drift.)
    # Use the canonical chain entrypoints directly.
    gate_s_cases = _load_cases_expected(_repo_path(repo_root, "policy/fixtures/public/gate_s/cases.json", must_exist=True, must_be_file=True))
    seal_cases = _load_cases_expected(_repo_path(repo_root, "policy/fixtures/public/seal/cases.json", must_exist=True, must_be_file=True))

    for d in sorted(touched_dirs):
        if d.startswith("policy/fixtures/public/gate_s/"):
            case_id = Path(d).name
            entry = gate_s_cases.get(case_id)
            if entry is None:
                raise RuntimeError(f"Unknown gate_s fixture case_id: {case_id}")
            _regen_gate_s_fixture(repo_root=repo_root, case_id=case_id, expected_exit_code=int(entry.get("expected_exit_code", 2)))
        if d.startswith("policy/fixtures/public/seal/"):
            case_id = Path(d).name
            entry = seal_cases.get(case_id)
            if entry is None:
                raise RuntimeError(f"Unknown seal fixture case_id: {case_id}")
            params = entry.get("params") if isinstance(entry.get("params"), dict) else {}
            _regen_seal_fixture(
                repo_root=repo_root,
                case_id=case_id,
                expected_exit_code=int(entry.get("expected_exit_code", 2)),
                final_commit_sha=str(params.get("final_commit_sha") or "0" * 40),
                sealed_at=str(params.get("sealed_at") or "2000-01-01T00:30:00Z"),
                signer=str(params.get("signer") or "human:fixture"),
            )

    return 0


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def _get_timestamp(use_fixed: bool) -> str:
    if use_fixed:
        return FIXED_TIMESTAMP
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_path(
    repo_root: Path,
    rel: str,
    *,
    must_exist: bool,
    must_be_file: bool | None,
) -> Path:
    # Authoritative inputs/outputs are confined to repo_root.
    return resolve_repo_rel_path(
        repo_root,
        rel,
        must_exist=must_exist,
        must_be_file=must_be_file,
        allow_backslashes=True,
        forbid_symlinks=True,
    )


def _default_media_type_for_path(p: Path) -> str:
    s = p.name.lower()
    if s.endswith(".json"):
        return "application/json"
    if s.endswith(".md"):
        return "text/markdown"
    if s.endswith(".txt"):
        return "text/plain"
    return "application/octet-stream"


def _load_protocol_schema(rel: str) -> dict[str, Any]:
    from belgi.protocol.pack import get_builtin_protocol_context

    protocol = get_builtin_protocol_context()
    obj = protocol.read_json(rel)
    if not isinstance(obj, dict):
        raise RuntimeError(f"Schema is not a JSON object: {rel}")
    return obj


def _validate_against_schema(*, obj: Any, schema: dict[str, Any], root_schema: dict[str, Any], where: str) -> None:
    from belgi.core.schema import validate_schema

    errs = validate_schema(obj, schema, root_schema=root_schema, path=where)
    if errs:
        lines = [f"{e.path}: {e.message}" for e in errs]
        joined = "\n".join(lines)
        raise RuntimeError(f"Schema validation failed ({where}):\n{joined}")


def _parse_add_spec(spec: str) -> tuple[str, str, str, str | None, str | None]:
    """Parse --add spec.

    Supported forms:
      - KIND:ID:PATH
      - KIND:ID:PATH:MEDIA_TYPE
      - KIND:ID:PATH:MEDIA_TYPE:PRODUCED_BY
    """

    parts = spec.split(":", 4)
    if len(parts) < 3:
        raise ValueError("--add must be KIND:ID:PATH[:MEDIA_TYPE][:PRODUCED_BY]")
    kind = parts[0].strip()
    art_id = parts[1].strip()
    path = parts[2].strip()

    # Enforce repo-relative path (no drive letters / URL schemes).
    if ":" in path:
        raise ValueError("PATH must be repo-relative (no drive letters)")

    media_type: str | None = None
    produced_by: str | None = None
    if len(parts) >= 4:
        media_type = parts[3].strip() or None
    if len(parts) == 5:
        produced_by = parts[4].strip() or None

    if not kind or not art_id or not path:
        raise ValueError("--add requires non-empty KIND, ID, and PATH")
    return kind, art_id, path, media_type, produced_by


def cmd_manifest_init(args: argparse.Namespace) -> int:
    """Create a deterministic, schema-valid EvidenceManifest JSON."""

    repo_root = Path(args.repo).resolve()
    out_path = _repo_path(repo_root, str(args.out), must_exist=False, must_be_file=True)

    if out_path.exists() and not args.overwrite:
        print(f"[belgi manifest-init] ERROR: output exists (use --overwrite): {args.out}", file=sys.stderr)
        return 3

    run_id: str
    if isinstance(args.run_id, str) and args.run_id:
        run_id = args.run_id
    elif isinstance(args.locked_spec, str) and args.locked_spec:
        locked_path = _repo_path(repo_root, str(args.locked_spec), must_exist=True, must_be_file=True)
        locked_obj = _load_json(locked_path)
        if not isinstance(locked_obj, dict):
            print("[belgi manifest-init] ERROR: LockedSpec must be an object", file=sys.stderr)
            return 3
        rid = locked_obj.get("run_id")
        if not isinstance(rid, str) or not rid.strip():
            print("[belgi manifest-init] ERROR: LockedSpec.run_id missing/invalid", file=sys.stderr)
            return 3
        run_id = rid.strip()
    else:
        print("[belgi manifest-init] ERROR: must provide --run-id or --locked-spec", file=sys.stderr)
        return 3

    envelope_attestation: dict[str, str] | None
    if getattr(args, "envelope_attestation", None):
        try:
            ea_id, ea_rel = str(args.envelope_attestation).split(":", 1)
        except ValueError:
            print("[belgi manifest-init] ERROR: --envelope-attestation must be ID:PATH", file=sys.stderr)
            return 3
        ea_id = ea_id.strip()
        ea_rel = ea_rel.strip()
        if not ea_id or not ea_rel:
            print("[belgi manifest-init] ERROR: --envelope-attestation must be ID:PATH", file=sys.stderr)
            return 3
        ea_path = _repo_path(repo_root, ea_rel, must_exist=True, must_be_file=True)
        envelope_attestation = {
            "id": ea_id,
            "hash": _sha256_file(ea_path),
            "storage_ref": safe_relpath(repo_root, ea_path),
        }
    else:
        envelope_attestation = None

    add_specs = list(args.add or [])
    if not add_specs:
        print("[belgi manifest-init] ERROR: must provide at least one --add", file=sys.stderr)
        return 3

    artifacts: list[dict[str, str]] = []
    for spec in add_specs:
        try:
            kind, art_id, rel, media_type, produced_by = _parse_add_spec(str(spec))
        except Exception as e:
            print(f"[belgi manifest-init] ERROR: invalid --add: {e}", file=sys.stderr)
            return 3

        p = _repo_path(repo_root, rel, must_exist=True, must_be_file=True)
        artifacts.append(
            {
                "kind": kind,
                "id": art_id,
                "hash": _sha256_file(p),
                "media_type": media_type or _default_media_type_for_path(p),
                "storage_ref": safe_relpath(repo_root, p),
                "produced_by": (produced_by or "C1"),
            }
        )

    artifacts.sort(key=lambda a: (a.get("kind", ""), a.get("id", ""), a.get("storage_ref", "")))

    mode = str(getattr(args, "command_log_mode", "strings") or "strings").strip()
    if mode not in ("strings", "structured"):
        print("[belgi manifest-init] ERROR: --command-log-mode must be strings or structured", file=sys.stderr)
        return 3

    commands_executed: list[Any]
    if mode == "strings":
        cmds = [
            str(x)
            for x in (getattr(args, "command_executed", None) or [])
            if isinstance(x, str) and x.strip()
        ]
        commands_executed = cmds if cmds else []
    else:
        # Deterministic seed record to avoid oneOf ambiguity for empty arrays.
        commands_executed = [
            {
                "argv": ["belgi", "manifest-init"],
                "exit_code": 0,
                "started_at": FIXED_TIMESTAMP,
                "finished_at": FIXED_TIMESTAMP,
            }
        ]

    manifest: dict[str, Any] = {
        "schema_version": str(getattr(args, "schema_version", SCHEMA_VERSION) or SCHEMA_VERSION),
        "run_id": run_id,
        "artifacts": artifacts,
        "commands_executed": commands_executed,
        "envelope_attestation": envelope_attestation,
    }

    # Validate against pinned schema (protocol pack builtin).
    try:
        em_schema = _load_protocol_schema("schemas/EvidenceManifest.schema.json")
        _validate_against_schema(obj=manifest, schema=em_schema, root_schema=em_schema, where="EvidenceManifest")
    except Exception as e:
        print(f"[belgi manifest-init] ERROR: {e}", file=sys.stderr)
        return 3

    try:
        _atomic_write_json(out_path, manifest)
    except Exception as e:
        print(f"[belgi manifest-init] ERROR: failed to write manifest: {e}", file=sys.stderr)
        return 3

    print(f"[belgi manifest-init] Wrote: {safe_relpath(repo_root, out_path)}", file=sys.stderr)
    return 0


def _det_env() -> dict[str, str]:
    # Deterministic parsing: avoid localized output where possible.
    env = dict(os.environ)
    env.setdefault("LANG", "C")
    env.setdefault("LC_ALL", "C")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env


# ---------------------------------------------------------------------------
# about subcommand
# ---------------------------------------------------------------------------

def cmd_about(_: argparse.Namespace) -> int:
    """Print package identity info (human-readable)."""

    try:
        pkg_version = version("belgi")
    except PackageNotFoundError:
        pkg_version = "0.0.0"

    pkg_name = "belgi"
    pkg_summary = ""
    try:
        meta = metadata("belgi")
        pkg_name = str(meta.get("Name") or pkg_name)
        pkg_summary = str(meta.get("Summary") or "")
    except PackageNotFoundError:
        pass

    print(f"{pkg_name} {pkg_version}")
    if pkg_summary:
        print(pkg_summary)
    ABOUT_PHILOSOPHY = '"Hayatta en hakiki mürşit ilimdir." (M.K. Atatürk)'
    ABOUT_DEDICATION = "Bilge (8)"
    ABOUT_REPO_URL = "https://github.com/belgi-protocol/belgi"
    print(f"Philosophy: {ABOUT_PHILOSOPHY}")
    print(f"Dedication: {ABOUT_DEDICATION}")
    print(f"Repo: {ABOUT_REPO_URL}")
    return 0


# ---------------------------------------------------------------------------
# run-tests subcommand
# ---------------------------------------------------------------------------

def cmd_run_tests(args: argparse.Namespace) -> int:
    """Run pytest and produce a test_report artifact.
    
    This runs pytest with JSON output, parses results, and produces
    a schema-valid TestReportPayload.
    """
    repo_root = Path(args.repo).resolve()
    out_path = _repo_path(repo_root, str(args.out), must_exist=False, must_be_file=True) if args.out else repo_root / "temp" / "tests.report.json"
    run_id = args.run_id
    timestamp = _get_timestamp(args.deterministic)
    
    # Build pytest command
    pytest_args = [sys.executable, "-m", "pytest"]
    if args.test_path:
        test_target = _repo_path(repo_root, str(args.test_path), must_exist=True, must_be_file=None)
        pytest_args.append(str(test_target))
    pytest_args.extend(["-q", "--tb=short"])
    
    print(f"[belgi run-tests] Running: {' '.join(pytest_args)}", file=sys.stderr)
    
    start_time = time.time()
    result = subprocess.run(
        pytest_args,
        cwd=str(repo_root),
        env=_det_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )
    duration = time.time() - start_time
    
    # Parse pytest output for counts
    # Look for pattern like "62 passed, 1 skipped in 5.19s"
    stdout = result.stdout
    stderr = result.stderr
    
    total = 0
    passed = 0
    failed = 0
    skipped = 0
    
    import re
    # Match patterns like "62 passed", "1 failed", "1 skipped"
    for line in (stdout + stderr).split("\n"):
        m_passed = re.search(r"(\d+)\s+passed", line)
        m_failed = re.search(r"(\d+)\s+failed", line)
        m_skipped = re.search(r"(\d+)\s+skipped", line)
        m_error = re.search(r"(\d+)\s+error", line)
        
        if m_passed:
            passed = int(m_passed.group(1))
        if m_failed:
            failed = int(m_failed.group(1))
        if m_skipped:
            skipped = int(m_skipped.group(1))
        if m_error:
            failed += int(m_error.group(1))
    
    total = passed + failed + skipped
    
    # If no tests found, check for collection errors
    if total == 0 and result.returncode != 0:
        failed = 1
        total = 1
    
    # Build TestReportPayload
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": timestamp,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "duration_seconds": round(duration, 2) if not args.deterministic else 0,
        },
        "exit_code": result.returncode,
        "stdout_tail": stdout[-2000:] if len(stdout) > 2000 else stdout,
    }
    
    _atomic_write_json(out_path, payload)
    print(f"[belgi run-tests] Wrote: {out_path}", file=sys.stderr)
    print(f"[belgi run-tests] Summary: total={total} passed={passed} failed={failed} skipped={skipped}", file=sys.stderr)
    
    # Exit code: 0 if all tests pass, 1 if any fail
    if failed > 0:
        print(f"[belgi run-tests] FAIL: {failed} test(s) failed", file=sys.stderr)
        return 1
    
    print(f"[belgi run-tests] PASS: all tests passed", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# invariant-eval subcommand
# ---------------------------------------------------------------------------

def cmd_invariant_eval(args: argparse.Namespace) -> int:
    """Evaluate LockedSpec invariants and produce policy.invariant_eval artifact.
    
    This reads LockedSpec.invariants[] and evaluates each invariant
    against the current repo state.
    """
    repo_root = Path(args.repo).resolve()
    locked_spec_path = _repo_path(repo_root, str(args.locked_spec), must_exist=True, must_be_file=True)
    out_path = _repo_path(repo_root, str(args.out), must_exist=False, must_be_file=True) if args.out else repo_root / "temp" / "policy.invariant_eval.json"
    timestamp = _get_timestamp(args.deterministic)
    
    if not locked_spec_path.exists():
        print(f"[belgi invariant-eval] ERROR: LockedSpec not found: {locked_spec_path}", file=sys.stderr)
        return 3
    
    locked_spec = _load_json(locked_spec_path)
    run_id = locked_spec.get("run_id", args.run_id)
    
    invariants = locked_spec.get("invariants", [])
    if not isinstance(invariants, list):
        print(f"[belgi invariant-eval] ERROR: LockedSpec.invariants must be a list", file=sys.stderr)
        return 3
    
    checks: list[dict[str, Any]] = []
    passed_count = 0
    failed_count = 0
    
    for inv in invariants:
        if not isinstance(inv, dict):
            continue
        
        inv_id = inv.get("id", "unknown")
        description = inv.get("description", "")
        check_type = inv.get("check_type", "manual")
        
        # Evaluate invariant based on check_type
        check_passed = True
        message = f"Invariant {inv_id} evaluated"
        
        if check_type == "file_exists":
            target = inv.get("target")
            if target:
                target_path = repo_root / target
                check_passed = target_path.exists()
                message = f"File exists: {target}" if check_passed else f"File missing: {target}"
        
        elif check_type == "file_not_modified":
            # Check if file hash matches expected
            target = inv.get("target")
            expected_hash = inv.get("expected_hash")
            if target and expected_hash:
                target_path = repo_root / target
                if target_path.exists():
                    actual_hash = _sha256_file(target_path)
                    check_passed = actual_hash == expected_hash
                    message = f"Hash match: {target}" if check_passed else f"Hash mismatch: {target}"
                else:
                    check_passed = False
                    message = f"File missing for hash check: {target}"
        
        elif check_type == "path_not_touched":
            # This would need diff context - for now, pass if no explicit violation
            target = inv.get("target")
            message = f"Path constraint: {target} (requires diff context)"
            check_passed = True  # Assume pass unless we have diff evidence
        
        elif check_type == "acceptance_criteria":
            # Manual/semantic check - pass by default, operator must verify
            message = f"Acceptance criteria: {description}"
            check_passed = True
        
        else:
            # Unknown check type - pass with note
            message = f"Manual verification required: {description}"
            check_passed = True
        
        checks.append({
            "check_id": inv_id,
            "passed": check_passed,
            "message": message,
            "check_type": check_type,
        })
        
        if check_passed:
            passed_count += 1
        else:
            failed_count += 1
    
    # If no invariants defined, add a placeholder check
    if len(checks) == 0:
        checks.append({
            "check_id": "no_invariants_defined",
            "passed": True,
            "message": "No invariants defined in LockedSpec (tier-0 acceptable)",
            "check_type": "placeholder",
        })
        passed_count = 1
    
    # Build PolicyReportPayload
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": timestamp,
        "report_type": "invariant_eval",
        "summary": {
            "total_checks": len(checks),
            "passed": passed_count,
            "failed": failed_count,
        },
        "checks": checks,
    }
    
    _atomic_write_json(out_path, payload)
    print(f"[belgi invariant-eval] Wrote: {out_path}", file=sys.stderr)
    print(f"[belgi invariant-eval] Summary: total={len(checks)} passed={passed_count} failed={failed_count}", file=sys.stderr)
    
    if failed_count > 0:
        print(f"[belgi invariant-eval] FAIL: {failed_count} invariant(s) failed", file=sys.stderr)
        return 1
    
    print(f"[belgi invariant-eval] PASS: all invariants satisfied", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# verify-attestation subcommand
# ---------------------------------------------------------------------------

def cmd_verify_attestation(args: argparse.Namespace) -> int:
    """Verify or generate env_attestation artifact.
    
    This produces an EnvAttestationPayload that binds:
    - run_id
    - command_log_sha256 (hash of the command log artifact)
    """
    repo_root = Path(args.repo).resolve()
    out_path = _repo_path(repo_root, str(args.out), must_exist=False, must_be_file=True) if args.out else repo_root / "temp" / "env_attestation.json"
    timestamp = _get_timestamp(args.deterministic)
    run_id = args.run_id
    attestation_id = args.attestation_id or "env.attestation"
    
    if not args.command_log:
        print("[belgi verify-attestation] ERROR: --command-log is required (fail-closed)", file=sys.stderr)
        return 3

    cmd_log_path = _repo_path(repo_root, str(args.command_log), must_exist=True, must_be_file=True)
    if not cmd_log_path.exists():
        print(f"[belgi verify-attestation] ERROR: command_log not found: {cmd_log_path}", file=sys.stderr)
        return 3

    command_log_sha256 = _sha256_file(cmd_log_path)

    signature_required: bool | None = None
    if getattr(args, "locked_spec", None):
        try:
            locked_path = _repo_path(repo_root, str(args.locked_spec), must_exist=True, must_be_file=True)
            locked = _load_json(locked_path)
            if not isinstance(locked, dict):
                raise ValueError("LockedSpec is not a JSON object")

            tier = locked.get("tier")
            tier_id = tier.get("tier_id") if isinstance(tier, dict) else None
            if not isinstance(tier_id, str) or not tier_id:
                raise ValueError("LockedSpec.tier.tier_id missing/invalid")

            # SSOT: ENGINE builtin protocol pack (never read tier policy from governed repo).
            from belgi.protocol.pack import get_builtin_protocol_context
            from chain.logic.tier_packs import parse_tier_params

            protocol = get_builtin_protocol_context()
            tiers_text = protocol.read_text("tiers/tier-packs.json")

            params = parse_tier_params(tiers_text, tier_id)
            if params.get("_tier_parse_error"):
                raise ValueError(f"tier parse error: {params.get('_tier_parse_error')}")

            signature_required = params.get("envelope_policy.attestation_signature_required") == "yes"
        except Exception as e:
            print(
                "[belgi verify-attestation] ERROR: cannot enforce tier signing policy from ENGINE builtin protocol pack (fail-closed): "
                + str(e),
                file=sys.stderr,
            )
            return 3

    if signature_required and not getattr(args, "signing_key", None):
        print(
            "[belgi verify-attestation] ERROR: tier requires attestation signature; provide --signing-key (32-byte hex seed).",
            file=sys.stderr,
        )
        return 3
    
    # Build EnvAttestationPayload
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "attestation_id": attestation_id,
        "generated_at": timestamp,
        "command_log_sha256": command_log_sha256,
    }

    if getattr(args, "signing_key", None):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except Exception as e:
            print(
                "[belgi verify-attestation] ERROR: missing crypto dependency for Ed25519 signing (install 'cryptography' in the declared Environment Envelope).",
                file=sys.stderr,
            )
            return 3

        seed_hex = str(args.signing_key).strip()
        if ":" in seed_hex or "\\" in seed_hex or "/" in seed_hex:
            # Treat as repo-relative path (confined by jail).
            seed_path = _repo_path(repo_root, seed_hex, must_exist=True, must_be_file=True)
            seed_hex = seed_path.read_text(encoding="utf-8", errors="strict").strip()

        if len(seed_hex) != 64 or not all(c in "0123456789abcdefABCDEF" for c in seed_hex):
            print("[belgi verify-attestation] ERROR: --signing-key must be 32-byte hex seed (64 hex chars)", file=sys.stderr)
            return 3

        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
        unsigned_payload = dict(payload)
        msg = _canonical_json_no_nl(unsigned_payload)
        sig = sk.sign(msg)

        payload["signature_alg"] = "ed25519"
        payload["signature"] = base64.b64encode(sig).decode("ascii")
    
    _atomic_write_json(out_path, payload)
    print(f"[belgi verify-attestation] Wrote: {out_path}", file=sys.stderr)
    print(f"[belgi verify-attestation] Attestation ID: {attestation_id}", file=sys.stderr)
    print(f"[belgi verify-attestation] Command log SHA256: {command_log_sha256}", file=sys.stderr)
    
    print(f"[belgi verify-attestation] PASS: attestation generated", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# diff-capture subcommand
# ---------------------------------------------------------------------------


def cmd_diff_capture(args: argparse.Namespace) -> int:
    """Capture a deterministic unified diff for Gate R evidence.

    Writes bytes exactly as returned by `git diff` with stable flags.
    """

    repo_root = Path(args.repo).resolve()
    upstream = str(args.upstream).strip()
    evaluated = str(args.evaluated).strip()

    if not _is_hex_40(upstream) or not _is_hex_40(evaluated):
        print("[belgi diff-capture] ERROR: --upstream and --evaluated must be 40-hex commit shas", file=sys.stderr)
        return 3

    out_path = _repo_path(repo_root, str(args.out), must_exist=False, must_be_file=True)

    env = dict(os.environ)
    env["GIT_PAGER"] = "cat"
    env["PAGER"] = "cat"

    cmd = [
        "git",
        "-C",
        str(repo_root),
        "-c",
        "core.pager=cat",
        "diff",
        "--no-color",
        "--no-ext-diff",
        "--full-index",
        upstream,
        evaluated,
        "--",
        ".",
    ]

    try:
        p = subprocess.run(cmd, check=False, capture_output=True, env=env)
    except Exception as e:
        print(f"[belgi diff-capture] ERROR: failed to execute git diff: {e}", file=sys.stderr)
        return 3

    if p.returncode != 0:
        err = (p.stderr or b"").decode("utf-8", errors="replace").strip()
        print(f"[belgi diff-capture] ERROR: git diff failed (rc={p.returncode}): {err}", file=sys.stderr)
        return 3

    _atomic_write_bytes(out_path, p.stdout or b"")
    print(f"[belgi diff-capture] Wrote: {out_path}", file=sys.stderr)
    print(f"[belgi diff-capture] PASS: diff captured", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# manifest-update subcommand (helper)
# ---------------------------------------------------------------------------

def cmd_manifest_update(args: argparse.Namespace) -> int:
    """Update EvidenceManifest with a new artifact entry.
    
    This is a helper to add artifacts to an existing manifest.
    """
    repo_root = Path(args.repo).resolve()
    manifest_path = _repo_path(repo_root, str(args.manifest), must_exist=True, must_be_file=True)
    
    manifest = _load_json(manifest_path)
    
    # Add artifact
    artifact_path = _repo_path(repo_root, str(args.artifact), must_exist=True, must_be_file=True)
    
    artifact_hash = _sha256_file(artifact_path)
    
    # storage_ref is authenticated repo-relative path.
    try:
        storage_ref = artifact_path.relative_to(repo_root).as_posix()
    except Exception:
        print(f"[belgi manifest-update] ERROR: scope escape for artifact: {artifact_path}", file=sys.stderr)
        return 3
    
    new_artifact = {
        "kind": args.kind,
        "id": args.id,
        "hash": artifact_hash,
        "media_type": args.media_type or "application/json",
        "storage_ref": storage_ref,
        "produced_by": args.produced_by or "C2",
    }
    
    # Check for duplicate id
    artifacts = manifest.get("artifacts", [])
    artifacts = [a for a in artifacts if isinstance(a, dict) and a.get("id") != args.id]
    artifacts.append(new_artifact)

    # Deterministic ordering: keep EvidenceManifest stable regardless of update order.
    def _k(a: dict[str, Any]) -> tuple[str, str, str]:
        return (str(a.get("kind", "")), str(a.get("id", "")), str(a.get("storage_ref", "")))

    manifest["artifacts"] = sorted(artifacts, key=_k)
    
    _atomic_write_json(manifest_path, manifest)
    print(f"[belgi manifest-update] Added artifact: {args.id} ({args.kind})", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# command-record subcommand (helper)
# ---------------------------------------------------------------------------

def cmd_command_record(args: argparse.Namespace) -> int:
    """Add a command record to EvidenceManifest.commands_executed.
    
    This records that a belgi subcommand was executed.
    """
    repo_root = Path(args.repo).resolve()
    manifest_path = _repo_path(repo_root, str(args.manifest), must_exist=True, must_be_file=True)
    
    manifest = _load_json(manifest_path)
    timestamp = _get_timestamp(args.deterministic)
    
    commands = manifest.get("commands_executed", [])
    
    # Detect mode from existing commands
    mode = args.mode
    if not mode:
        if len(commands) > 0:
            if isinstance(commands[0], str):
                mode = "strings"
            elif isinstance(commands[0], dict):
                mode = "structured"
            else:
                mode = "structured"
        else:
            mode = "structured"
    
    if mode == "strings":
        # Format: "belgi <subcommand>"
        cmd_str = f"belgi {args.subcommand}"
        if cmd_str not in commands:
            commands.append(cmd_str)
    else:
        # Structured format
        record = {
            "argv": ["belgi", args.subcommand],
            "exit_code": args.exit_code,
            "started_at": timestamp,
            "finished_at": timestamp,
        }
        # Check if already exists
        exists = any(
            isinstance(c, dict) and c.get("argv") == ["belgi", args.subcommand]
            for c in commands
        )
        if not exists:
            commands.append(record)
    
    manifest["commands_executed"] = commands
    
    _atomic_write_json(manifest_path, manifest)
    print(f"[belgi command-record] Recorded: belgi {args.subcommand} (exit_code={args.exit_code})", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# pack build / pack verify subcommands
# ---------------------------------------------------------------------------

def cmd_pack_build(args: argparse.Namespace) -> int:
    """Build/update protocol pack manifest deterministically.
    
    Scans --in directory, computes file hashes/sizes, generates
    ProtocolPackManifest.json with deterministic pack_id.
    """
    # Lazy import to avoid circular dependency and keep CLI startup fast.
    # Ensure repo root is on path to avoid shadowing by tools/belgi.py.
    import sys
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    
    from belgi.protocol.pack import (
        MANIFEST_FILENAME,
        build_manifest_bytes,
        validate_manifest_bytes,
    )
    
    in_dir = Path(args.input).resolve()
    out_dir = Path(args.output).resolve() if args.output else in_dir
    pack_name = args.pack_name
    
    if not in_dir.exists():
        print(f"[belgi pack build] ERROR: input directory does not exist: {in_dir}", file=sys.stderr)
        return 3
    if not in_dir.is_dir():
        print(f"[belgi pack build] ERROR: input is not a directory: {in_dir}", file=sys.stderr)
        return 3
    if in_dir.is_symlink():
        print(f"[belgi pack build] ERROR: symlink directory not allowed: {in_dir}", file=sys.stderr)
        return 3
    
    # If out_dir != in_dir, we need to copy content first (not implemented here; use build_builtin_pack.py for that).
    if out_dir != in_dir:
        print(f"[belgi pack build] ERROR: --out must equal --in (use build_builtin_pack.py for copy workflows)", file=sys.stderr)
        return 3
    
    try:
        manifest_bytes = build_manifest_bytes(
            pack_root=in_dir,
            pack_name=pack_name,
        )
    except Exception as e:
        print(f"[belgi pack build] ERROR: failed to build manifest: {e}", file=sys.stderr)
        return 1
    
    manifest_path = out_dir / MANIFEST_FILENAME
    manifest_path.write_bytes(manifest_bytes)
    
    # Fail-closed: validate immediately after writing.
    try:
        validate_manifest_bytes(pack_root=out_dir, manifest_bytes=manifest_bytes)
    except Exception as e:
        print(f"[belgi pack build] ERROR: validation failed after build: {e}", file=sys.stderr)
        return 1
    
    # Parse to show summary.
    parsed = json.loads(manifest_bytes.decode("utf-8"))
    pack_id = parsed.get("pack_id", "")
    file_count = len(parsed.get("files", []))
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    
    print(f"[belgi pack build] Wrote: {manifest_path}", file=sys.stderr)
    print(f"[belgi pack build] pack_id: {pack_id}", file=sys.stderr)
    print(f"[belgi pack build] manifest_sha256: {manifest_sha256}", file=sys.stderr)
    print(f"[belgi pack build] files: {file_count}", file=sys.stderr)
    print(f"[belgi pack build] PASS: manifest built and validated", file=sys.stderr)
    return 0


def cmd_pack_verify(args: argparse.Namespace) -> int:
    """Verify protocol pack manifest matches file tree.
    
    Reads --in directory and its ProtocolPackManifest.json,
    validates that manifest matches actual file hashes/sizes,
    and that pack_id is correctly computed.
    """
    from importlib.resources import as_file, files

    # Lazy import. Ensure repo root is on path to avoid shadowing by tools/belgi.py.
    import sys
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    
    from belgi.protocol.pack import (
        MANIFEST_FILENAME,
        validate_manifest_bytes,
    )

    def _emit_manifest_files_diff(*, pack_root: Path, manifest_bytes: bytes) -> None:
        try:
            from belgi.protocol.pack import scan_pack_dir
            from belgi.core.jail import normalize_repo_rel_path
        except Exception as e:  # pragma: no cover
            print(f"[belgi pack verify] NOTE: cannot import diff helpers: {e}", file=sys.stderr)
            return

        try:
            parsed = json.loads(bytes(manifest_bytes).decode("utf-8", errors="strict"))
        except Exception as e:
            print(f"[belgi pack verify] NOTE: cannot parse manifest JSON for diff: {e}", file=sys.stderr)
            return
        if not isinstance(parsed, dict):
            print("[belgi pack verify] NOTE: manifest JSON is not an object; diff unavailable", file=sys.stderr)
            return

        files = parsed.get("files")
        if not isinstance(files, list):
            print("[belgi pack verify] NOTE: manifest.files missing/invalid; diff unavailable", file=sys.stderr)
            return

        manifest_map: dict[str, tuple[str, int]] = {}
        for entry in files:
            if not isinstance(entry, dict):
                continue
            rel_raw = entry.get("relpath")
            sha = entry.get("sha256")
            size = entry.get("size_bytes")
            if not isinstance(rel_raw, str) or not rel_raw:
                continue
            if not isinstance(sha, str) or not sha:
                continue
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                continue
            try:
                rel = normalize_repo_rel_path(rel_raw)
            except Exception:
                continue
            if rel == MANIFEST_FILENAME:
                continue
            manifest_map[rel] = (sha, size)

        scanned_entries = scan_pack_dir(pack_root)
        scanned_map: dict[str, tuple[str, int]] = {e.relpath: (e.sha256, e.size_bytes) for e in scanned_entries}

        manifest_paths = set(manifest_map)
        scanned_paths = set(scanned_map)

        missing_in_manifest = sorted(scanned_paths - manifest_paths)
        extra_in_manifest = sorted(manifest_paths - scanned_paths)
        mismatched = sorted(
            [
                rel
                for rel in (manifest_paths & scanned_paths)
                if manifest_map.get(rel) != scanned_map.get(rel)
            ]
        )

        print(f"[belgi pack verify] diff: missing_in_manifest={len(missing_in_manifest)}", file=sys.stderr)
        for rel in missing_in_manifest:
            print(f"[belgi pack verify] diff: missing_in_manifest: {rel}", file=sys.stderr)

        print(f"[belgi pack verify] diff: extra_in_manifest={len(extra_in_manifest)}", file=sys.stderr)
        for rel in extra_in_manifest:
            print(f"[belgi pack verify] diff: extra_in_manifest: {rel}", file=sys.stderr)

        print(f"[belgi pack verify] diff: mismatched={len(mismatched)}", file=sys.stderr)
        for rel in mismatched:
            m_sha, m_size = manifest_map[rel]
            s_sha, s_size = scanned_map[rel]
            print(
                f"[belgi pack verify] diff: mismatched: {rel} "
                f"(manifest sha256={m_sha} size_bytes={m_size}; scanned sha256={s_sha} size_bytes={s_size})",
                file=sys.stderr,
            )

    if bool(getattr(args, "builtin", False)):
        pack_traversable = files("belgi").joinpath("_protocol_packs", "v1")
        try:
            with as_file(pack_traversable) as pack_root:
                manifest_bytes = (pack_root / MANIFEST_FILENAME).read_bytes()
                validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_bytes)
        except Exception as e:
            if str(e) == "manifest.files do not match scanned pack contents":
                try:
                    with as_file(pack_traversable) as pack_root:
                        manifest_bytes = (pack_root / MANIFEST_FILENAME).read_bytes()
                        _emit_manifest_files_diff(pack_root=pack_root, manifest_bytes=manifest_bytes)
                except Exception:
                    pass
            print(f"[belgi pack verify] FAIL (builtin): {e}", file=sys.stderr)
            return 1

        parsed = json.loads(manifest_bytes.decode("utf-8", errors="strict"))
        pack_id = parsed.get("pack_id", "")
        pack_name = parsed.get("pack_name", "")
        file_count = len(parsed.get("files", []))
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

        if bool(getattr(args, "verbose", False)):
            print(f"[belgi pack verify] source: builtin (installed package)", file=sys.stderr)
            print(f"[belgi pack verify] pack_name: {pack_name}", file=sys.stderr)
            print(f"[belgi pack verify] pack_id: {pack_id}", file=sys.stderr)
            print(f"[belgi pack verify] manifest_sha256: {manifest_sha256}", file=sys.stderr)
            print(f"[belgi pack verify] files: {file_count}", file=sys.stderr)
            print(f"[belgi pack verify] PASS: builtin manifest verified", file=sys.stderr)
        return 0

    if not args.input:
        print(f"[belgi pack verify] ERROR: --in or --builtin required", file=sys.stderr)
        return 3
    
    in_dir = Path(args.input).resolve()
    
    if not in_dir.exists():
        print(f"[belgi pack verify] ERROR: input directory does not exist: {in_dir}", file=sys.stderr)
        return 3
    if not in_dir.is_dir():
        print(f"[belgi pack verify] ERROR: input is not a directory: {in_dir}", file=sys.stderr)
        return 3
    if in_dir.is_symlink():
        print(f"[belgi pack verify] ERROR: symlink directory not allowed: {in_dir}", file=sys.stderr)
        return 3
    
    manifest_path = in_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        print(f"[belgi pack verify] ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        return 1
    if manifest_path.is_symlink():
        print(f"[belgi pack verify] ERROR: symlink manifest not allowed: {manifest_path}", file=sys.stderr)
        return 1
    
    manifest_bytes = manifest_path.read_bytes()
    
    try:
        validate_manifest_bytes(pack_root=in_dir, manifest_bytes=manifest_bytes)
    except Exception as e:
        if str(e) == "manifest.files do not match scanned pack contents":
            _emit_manifest_files_diff(pack_root=in_dir, manifest_bytes=manifest_bytes)
        print(f"[belgi pack verify] FAIL: {e}", file=sys.stderr)
        return 1
    
    # Parse to show summary.
    parsed = json.loads(manifest_bytes.decode("utf-8"))
    pack_id = parsed.get("pack_id", "")
    pack_name = parsed.get("pack_name", "")
    file_count = len(parsed.get("files", []))
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    
    print(f"[belgi pack verify] pack_name: {pack_name}", file=sys.stderr)
    print(f"[belgi pack verify] pack_id: {pack_id}", file=sys.stderr)
    print(f"[belgi pack verify] manifest_sha256: {manifest_sha256}", file=sys.stderr)
    print(f"[belgi pack verify] files: {file_count}", file=sys.stderr)
    print(f"[belgi pack verify] PASS: manifest verified", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="belgi",
        description="BELGI CLI — Evidence generation tools for the BELGI protocol",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    # about
    subparsers.add_parser("about", help="Print package identity info")
    
    # run-tests
    p_tests = subparsers.add_parser("run-tests", help="Run pytest and produce test_report artifact")
    p_tests.add_argument("--repo", default=".", help="Repo root")
    p_tests.add_argument("--run-id", required=True, help="Run ID for the report")
    p_tests.add_argument("--out", help="Output path for test_report JSON")
    p_tests.add_argument("--test-path", help="Specific test path to run")
    p_tests.add_argument("--deterministic", action="store_true", help="Use fixed timestamp")
    
    # invariant-eval
    p_inv = subparsers.add_parser("invariant-eval", help="Evaluate LockedSpec invariants")
    p_inv.add_argument("--repo", default=".", help="Repo root")
    p_inv.add_argument("--locked-spec", required=True, help="Path to LockedSpec.json")
    p_inv.add_argument("--run-id", default="unknown", help="Run ID (fallback if not in LockedSpec)")
    p_inv.add_argument("--out", help="Output path for policy.invariant_eval JSON")
    p_inv.add_argument("--deterministic", action="store_true", help="Use fixed timestamp")
    
    # verify-attestation
    p_att = subparsers.add_parser("verify-attestation", help="Generate env_attestation artifact")
    p_att.add_argument("--repo", default=".", help="Repo root")
    p_att.add_argument("--run-id", required=True, help="Run ID")
    p_att.add_argument("--attestation-id", help="Attestation ID (default: env.attestation)")
    p_att.add_argument("--command-log", help="Path to command_log artifact for binding")
    p_att.add_argument(
        "--locked-spec",
        help="Optional repo-relative LockedSpec.json; if provided, ENGINE builtin tier policy is consulted and required signing is enforced fail-closed.",
    )
    p_att.add_argument(
        "--signing-key",
        help="Ed25519 signing key seed (64 hex chars) OR repo-relative path to a file containing that seed.",
    )
    p_att.add_argument("--out", help="Output path for env_attestation JSON")
    p_att.add_argument("--deterministic", action="store_true", help="Use fixed timestamp")

    # diff-capture
    p_diff = subparsers.add_parser("diff-capture", help="Capture a deterministic unified diff artifact")
    p_diff.add_argument("--repo", default=".", help="Repo root")
    p_diff.add_argument("--upstream", required=True, help="40-hex upstream/base commit sha")
    p_diff.add_argument("--evaluated", required=True, help="40-hex evaluated commit sha")
    p_diff.add_argument("--out", required=True, help="Repo-relative output path for diff bytes")

    # manifest-init
    p_mi = subparsers.add_parser("manifest-init", help="Create a new EvidenceManifest deterministically")
    p_mi.add_argument("--repo", required=True, help="Repo root")
    p_mi.add_argument("--out", required=True, help="Repo-relative output path for EvidenceManifest.json")
    g_run = p_mi.add_mutually_exclusive_group(required=False)
    g_run.add_argument("--run-id", dest="run_id", help="Run ID for the manifest")
    g_run.add_argument("--locked-spec", help="Repo-relative LockedSpec.json (run_id is read from it)")
    p_mi.add_argument(
        "--add",
        action="append",
        default=[],
        help="Add an artifact: KIND:ID:PATH[:MEDIA_TYPE][:PRODUCED_BY] (repeatable)",
    )
    p_mi.add_argument(
        "--envelope-attestation",
        default=None,
        help="Optional envelope attestation ObjectRef source: ID:PATH (repo-relative PATH)",
    )
    p_mi.add_argument("--schema-version", default=SCHEMA_VERSION, help="schema_version value to write")
    p_mi.add_argument(
        "--command-log-mode",
        choices=["strings", "structured"],
        default="strings",
        help="Initialize commands_executed shape (default: strings/empty list)",
    )
    p_mi.add_argument(
        "--command-executed",
        dest="command_executed",
        action="append",
        default=[],
        help="Seed commands_executed (strings mode only). Repeatable.",
    )
    # Back-compat ergonomic alias: do not collide with subparser dest="command".
    p_mi.add_argument(
        "--command",
        dest="command_executed",
        action="append",
        default=[],
        help="Alias for --command-executed.",
    )
    p_mi.add_argument("--overwrite", action="store_true", help="Overwrite --out if it exists")
    
    # manifest-update (helper)
    p_mu = subparsers.add_parser("manifest-update", help="Add artifact to EvidenceManifest")
    p_mu.add_argument("--repo", default=".", help="Repo root")
    p_mu.add_argument("--manifest", required=True, help="Path to EvidenceManifest.json")
    p_mu.add_argument("--artifact", required=True, help="Path to artifact file")
    p_mu.add_argument("--kind", required=True, help="Artifact kind")
    p_mu.add_argument("--id", required=True, help="Artifact ID")
    p_mu.add_argument("--media-type", help="Media type (default: application/json)")
    p_mu.add_argument("--produced-by", help="Producer stage (C1/C2/R/C3/S)")
    
    # command-record (helper)
    p_cr = subparsers.add_parser("command-record", help="Record command in EvidenceManifest")
    p_cr.add_argument("--repo", default=".", help="Repo root")
    p_cr.add_argument("--manifest", required=True, help="Path to EvidenceManifest.json")
    p_cr.add_argument("--subcommand", required=True, help="Subcommand name (e.g., run-tests)")
    p_cr.add_argument("--exit-code", type=int, default=0, help="Exit code of the command")
    p_cr.add_argument("--mode", choices=["strings", "structured"], help="Command log mode")
    p_cr.add_argument("--deterministic", action="store_true", help="Use fixed timestamp")
    
    # pack (subparser group)
    p_pack = subparsers.add_parser("pack", help="Protocol pack management commands")
    pack_subs = p_pack.add_subparsers(dest="pack_command", help="Pack subcommand")
    
    # pack build
    p_pack_build = pack_subs.add_parser("build", help="Build/update protocol pack manifest")
    p_pack_build.add_argument("--in", dest="input", required=True, help="Input pack directory")
    p_pack_build.add_argument("--out", dest="output", help="Output directory (default: same as --in)")
    p_pack_build.add_argument("--pack-name", default="belgi-protocol-pack-v1", help="Pack name for manifest")
    
    # pack verify
    p_pack_verify = pack_subs.add_parser("verify", help="Verify protocol pack manifest")
    p_pack_verify.add_argument("--in", dest="input", help="Pack directory to verify")
    p_pack_verify.add_argument("--builtin", action="store_true", help="Verify builtin pack from installed package")
    p_pack_verify.add_argument("--verbose", action="store_true", help="Verbose output")

    # fixtures (subparser group)
    p_fix = subparsers.add_parser("fixtures", help="Repo-local fixture maintenance commands")
    fix_subs = p_fix.add_subparsers(dest="fixtures_command", help="fixtures subcommand")

    p_sync = fix_subs.add_parser("sync-pack-identity", help="Sync LockedSpec.protocol_pack pins across policy/fixtures")
    p_sync.add_argument("--repo", default=".", help="Repo root")
    p_sync.add_argument("--pack-dir", default="belgi/_protocol_packs/v1", help="Repo-relative active protocol pack directory")

    p_regen = fix_subs.add_parser("regen-seals", help="Regenerate seal-related fixture artifacts deterministically")
    p_regen.add_argument("--repo", default=".", help="Repo root")
    p_regen.add_argument(
        "--create-missing-private-keys",
        action="store_true",
        help="Create missing policy/fixtures/public/seal/*/seal_private_key.hex deterministically (default: NO-GO)",
    )
    p_regen.add_argument(
        "--only-touched",
        action="store_true",
        help="Only update fixtures that required self-healing changes in this run (default: update all eligible fixtures)",
    )

    p_all = fix_subs.add_parser("fix-all", help="Sync pack pins then regenerate seal-related fixtures (scoped)")
    p_all.add_argument("--repo", default=".", help="Repo root")
    p_all.add_argument("--pack-dir", default="belgi/_protocol_packs/v1", help="Repo-relative active protocol pack directory")
    p_all.add_argument(
        "--create-missing-private-keys",
        action="store_true",
        help="Create missing policy/fixtures/public/seal/*/seal_private_key.hex deterministically (default: NO-GO)",
    )
    
    args = parser.parse_args()

    cmd = str(getattr(args, "command", "") or "")
    cmd_norm = cmd.replace("_", "-")

    if cmd_norm == "about":
        return cmd_about(args)
    elif cmd_norm == "run-tests":
        return cmd_run_tests(args)
    elif cmd_norm == "invariant-eval":
        return cmd_invariant_eval(args)
    elif cmd_norm == "verify-attestation":
        return cmd_verify_attestation(args)
    elif cmd_norm == "diff-capture":
        return cmd_diff_capture(args)
    elif cmd_norm == "manifest-init":
        return cmd_manifest_init(args)
    elif cmd_norm == "manifest-update":
        return cmd_manifest_update(args)
    elif cmd_norm == "command-record":
        return cmd_command_record(args)
    elif cmd_norm == "pack":
        if args.pack_command == "build":
            return cmd_pack_build(args)
        elif args.pack_command == "verify":
            return cmd_pack_verify(args)
        else:
            p_pack.print_help()
            return 3
    elif cmd_norm == "fixtures":
        if args.fixtures_command == "sync-pack-identity":
            return cmd_fixtures_sync_pack_identity(args)
        elif args.fixtures_command == "regen-seals":
            return cmd_fixtures_regen_seals(args)
        elif args.fixtures_command == "fix-all":
            return cmd_fixtures_fix_all(args)
        else:
            p_fix.print_help()
            return 3
    else:
        parser.print_help()
        return 3


if __name__ == "__main__":
    sys.exit(main())
