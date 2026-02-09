#!/usr/bin/env python3
"""Unified hasher/rehash entrypoint.

Commands:
- sha256-txt: rehash or check sha256sum-style manifest files
- evidence-manifest: recompute hashes inside EvidenceManifest.json
- required-reports: rehash required policy/test report ObjectRefs in fixture manifests

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

    from belgi.protocol.pack import MANIFEST_FILENAME, build_manifest_bytes, validate_manifest_bytes

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


def _extract_case_path(case: dict[str, Any], key: str) -> str | None:
    v = case.get(key)
    if isinstance(v, str) and v:
        return v
    paths = case.get("paths")
    if isinstance(paths, dict):
        pv = paths.get(key)
        if isinstance(pv, str) and pv:
            return pv
    return None


def _cmd_fixtures_protocol_pack(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Update/check fixture LockedSpec.protocol_pack pins to match builtin protocol pack")
    ap.add_argument("--repo", default=".", help="Repo root")
    ap.add_argument(
        "--pack",
        default="belgi/_protocol_packs/v1",
        help="Protocol pack root directory (repo-relative)",
    )
    ap.add_argument(
        "--cases-q",
        default="policy/fixtures/public/gate_q/cases.json",
        help="Gate Q cases.json path (repo-relative)",
    )
    ap.add_argument(
        "--cases-r",
        default="policy/fixtures/public/gate_r/cases.json",
        help="Gate R cases.json path (repo-relative)",
    )
    ap.add_argument(
        "--gates",
        choices=["q", "r", "qr"],
        default="qr",
        help="Which fixture sets to update/check",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Validate pins match current pack without rewriting (exit 2 on mismatch)",
    )
    args = ap.parse_args(argv)

    repo_root = Path(args.repo).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        raise _UserInputError(f"repo root is not a directory: {repo_root}")

    pack_rel = _validate_repo_rel(str(args.pack))
    pack_dir = _resolve_repo_dir(repo_root, pack_rel)

    from belgi.protocol.pack import MANIFEST_FILENAME, validate_manifest_bytes

    manifest_path = pack_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        print(f"NO-GO: manifest missing: {pack_rel}/{MANIFEST_FILENAME}")
        return 2
    manifest_bytes = manifest_path.read_bytes()
    try:
        validate_manifest_bytes(pack_root=pack_dir, manifest_bytes=manifest_bytes)
    except Exception as e:
        print(f"NO-GO: protocol pack manifest invalid: {pack_rel}/{MANIFEST_FILENAME}: {e}")
        return 2

    parsed = json.loads(manifest_bytes.decode("utf-8", errors="strict"))
    if not isinstance(parsed, dict):
        print("NO-GO: manifest JSON is not an object")
        return 2
    pack_id = parsed.get("pack_id")
    if not isinstance(pack_id, str) or not pack_id:
        print("NO-GO: manifest.pack_id missing/invalid")
        return 2
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    targets: list[Path] = []
    if args.gates in ("q", "qr"):
        cases_q_rel = _validate_repo_rel(str(args.cases_q))
        cases_q_path = _resolve_repo_file(repo_root, cases_q_rel)
        cases_q_obj = _load_json(cases_q_path)
        if not isinstance(cases_q_obj, dict) or not isinstance(cases_q_obj.get("cases"), list):
            raise _UserInputError("Gate Q cases.json must be an object with a cases[] list")
        for c in sorted(cases_q_obj["cases"], key=lambda x: str(x.get("case_id", "")) if isinstance(x, dict) else ""):
            if not isinstance(c, dict):
                continue
            p = _extract_case_path(c, "locked_spec")
            if not p:
                continue
            targets.append(_resolve_repo_file(repo_root, p.replace("\\", "/")))

    if args.gates in ("r", "qr"):
        cases_r_rel = _validate_repo_rel(str(args.cases_r))
        cases_r_path = _resolve_repo_file(repo_root, cases_r_rel)
        cases_r_obj = _load_json(cases_r_path)
        if not isinstance(cases_r_obj, dict) or not isinstance(cases_r_obj.get("cases"), list):
            raise _UserInputError("Gate R cases.json must be an object with a cases[] list")
        for c in sorted(cases_r_obj["cases"], key=lambda x: str(x.get("case_id", "")) if isinstance(x, dict) else ""):
            if not isinstance(c, dict):
                continue
            p = _extract_case_path(c, "locked_spec")
            if not p:
                continue
            targets.append(_resolve_repo_file(repo_root, p.replace("\\", "/")))

    # Deduplicate deterministically.
    uniq: dict[str, Path] = {}
    for p in targets:
        rel = p.relative_to(repo_root.resolve()).as_posix()
        uniq[rel] = p
    locked_specs = [uniq[k] for k in sorted(uniq.keys())]

    if not locked_specs:
        print("NO-GO: no LockedSpec targets found (checked 0)")
        return 2

    mismatches: list[str] = []
    changed = 0

    for ls_path in locked_specs:
        rel = ls_path.relative_to(repo_root.resolve()).as_posix()
        doc = _load_json(ls_path)
        if not isinstance(doc, dict):
            mismatches.append(f"{rel}: LockedSpec is not an object")
            continue
        pp = doc.get("protocol_pack")
        if not isinstance(pp, dict):
            mismatches.append(f"{rel}: protocol_pack missing/invalid")
            continue

        old_pack_id = pp.get("pack_id")
        old_msha = pp.get("manifest_sha256")
        needs = (old_pack_id != pack_id) or (old_msha != manifest_sha256)

        if args.check:
            if needs:
                mismatches.append(
                    f"{rel}: protocol_pack pin mismatch pack_id={str(old_pack_id)[:8]}.. manifest_sha256={str(old_msha)[:8]}.."
                )
            continue

        if needs:
            pp["pack_id"] = pack_id
            pp["manifest_sha256"] = manifest_sha256
            _dump_json_preserve_order(ls_path, doc)
            changed += 1

    if args.check:
        if mismatches:
            print(f"NO-GO: fixture LockedSpec protocol_pack pins mismatched: {len(mismatches)}/{len(locked_specs)}")
            for m in mismatches[:8]:
                print(m)
            return 2
        print(f"PASS: fixture LockedSpec protocol_pack pins match: {len(locked_specs)}/{len(locked_specs)}")
        return 0

    if mismatches:
        print(f"NO-GO: invalid LockedSpec(s): {len(mismatches)}")
        for m in mismatches[:8]:
            print(m)
        return 2

    print(f"Updated LockedSpecs: {changed}/{len(locked_specs)}")
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
        raise SystemExit("EvidenceManifest must be a JSON object")

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


_REQUIRED_POLICY_REPORT_IDS = [
    "policy.invariant_eval",
    "policy.supplychain",
    "policy.adversarial_scan",
    "policy.consistency_sweep",
]

_REQUIRED_TEST_REPORT_IDS = [
    "tests.report",
]


def _find_artifact(manifest: dict[str, Any], *, kind: str, artifact_id: str) -> dict[str, Any] | None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return None
    matches = [
        a
        for a in artifacts
        if isinstance(a, dict) and a.get("kind") == kind and a.get("id") == artifact_id
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _rehash_one_required_reports(
    *,
    repo_root: Path,
    evidence_manifest_rel: str,
    expected_fail_check_ids: set[str],
    strict_required: bool,
) -> tuple[bool, list[str]]:
    em_path = _resolve_repo_file(repo_root, evidence_manifest_rel)
    manifest = _load_json(em_path)
    if not isinstance(manifest, dict):
        raise _UserInputError(f"EvidenceManifest is not an object: {evidence_manifest_rel}")

    changed = False
    notes: list[str] = []
    errors = 0

    for rid in _REQUIRED_POLICY_REPORT_IDS:
        check_id = (
            "consistency_sweep.index_fixed"
            if rid == "policy.consistency_sweep"
            else f"objectref_bytes_hash.policy_report.{rid}"
        )
        if check_id in expected_fail_check_ids:
            notes.append(f"skip intentional {check_id}")
            continue

        art = _find_artifact(manifest, kind="policy_report", artifact_id=rid)
        if art is None:
            notes.append(f"missing/ambiguous policy_report:{rid}")
            if strict_required:
                errors += 1
            continue

        storage_ref = art.get("storage_ref")
        if not isinstance(storage_ref, str) or not storage_ref:
            notes.append(f"invalid storage_ref policy_report:{rid}")
            if strict_required:
                errors += 1
            continue

        try:
            ref_path = _resolve_repo_file(repo_root, storage_ref)
        except _UserInputError:
            notes.append(f"storage_ref missing/invalid policy_report:{rid} -> {storage_ref}")
            if strict_required:
                errors += 1
            continue

        new_hash = _sha256_file(ref_path)
        old_hash = art.get("hash")
        if old_hash != new_hash:
            art["hash"] = new_hash
            changed = True
            notes.append(f"update policy_report:{rid} {str(old_hash)[:8]}.. -> {new_hash[:8]}..")

    for rid in _REQUIRED_TEST_REPORT_IDS:
        check_id = f"objectref_bytes_hash.test_report.{rid}"
        if check_id in expected_fail_check_ids:
            notes.append(f"skip intentional {check_id}")
            continue

        art = _find_artifact(manifest, kind="test_report", artifact_id=rid)
        if art is None:
            notes.append(f"missing/ambiguous test_report:{rid}")
            if strict_required:
                errors += 1
            continue

        storage_ref = art.get("storage_ref")
        if not isinstance(storage_ref, str) or not storage_ref:
            notes.append(f"invalid storage_ref test_report:{rid}")
            if strict_required:
                errors += 1
            continue

        try:
            ref_path = _resolve_repo_file(repo_root, storage_ref)
        except _UserInputError:
            notes.append(f"storage_ref missing/invalid test_report:{rid} -> {storage_ref}")
            if strict_required:
                errors += 1
            continue

        new_hash = _sha256_file(ref_path)
        old_hash = art.get("hash")
        if old_hash != new_hash:
            art["hash"] = new_hash
            changed = True
            notes.append(f"update test_report:{rid} {str(old_hash)[:8]}.. -> {new_hash[:8]}..")

    if changed:
        _dump_json(em_path, manifest)

    if errors:
        notes.append(f"errors:{errors}")

    return changed, notes


def _cmd_required_reports(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Re-hash required report ObjectRefs in fixture EvidenceManifest.json files")
    ap.add_argument("--repo", default=".", help="Repo root")
    ap.add_argument(
        "--cases",
        default="policy/fixtures/public/gate_r/cases.json",
        help="Cases JSON (repo-relative)",
    )
    ap.add_argument(
        "--demo-manifest",
        default="",
        help="Optional demo EvidenceManifest.json to rehash first (repo-relative)",
    )
    ap.add_argument(
        "--allow-empty",
        action="store_true",
        help="Allow zero targets (default: NO-GO)",
    )
    args = ap.parse_args(argv)

    repo_root = Path(args.repo).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        raise _UserInputError(f"repo root is not a directory: {repo_root}")

    cases_rel = _validate_repo_rel(str(args.cases))
    cases_path = _resolve_repo_file(repo_root, cases_rel)

    cases_obj = _load_json(cases_path)
    if not isinstance(cases_obj, dict) or not isinstance(cases_obj.get("cases"), list):
        raise _UserInputError("cases.json must be an object with a cases[] list")

    total_changed = 0
    total_targets = 0
    total_errors = 0

    if args.demo_manifest:
        demo_rel = str(args.demo_manifest).replace("\\", "/")
        demo_changed, _demo_notes = _rehash_one_required_reports(
            repo_root=repo_root,
            evidence_manifest_rel=demo_rel,
            expected_fail_check_ids=set(),
            strict_required=True,
        )
        total_targets += 1
        if demo_changed:
            total_changed += 1

        if any(n.startswith("errors:") for n in _demo_notes):
            total_errors += 1

    for c in sorted(cases_obj["cases"], key=lambda x: str(x.get("case_id", ""))):
        if not isinstance(c, dict):
            continue
        case_id = str(c.get("case_id") or "")

        em_rel: str | None = None
        if isinstance(c.get("evidence_manifest"), str):
            em_rel = str(c.get("evidence_manifest") or "")
        else:
            paths = c.get("paths")
            if isinstance(paths, dict) and isinstance(paths.get("evidence_manifest"), str):
                em_rel = str(paths.get("evidence_manifest") or "")
        if not em_rel:
            continue

        expected_fail = c.get("expected_fail_check_ids")
        expected_fail_ids: set[str] = set(expected_fail) if isinstance(expected_fail, list) else set()

        expected_exit_code = c.get("expected_exit_code")
        strict_required = expected_exit_code == 0

        total_targets += 1
        changed, notes = _rehash_one_required_reports(
            repo_root=repo_root,
            evidence_manifest_rel=em_rel,
            expected_fail_check_ids=expected_fail_ids,
            strict_required=strict_required,
        )
        if changed:
            total_changed += 1
        if notes:
            print(f"{case_id}: {'; '.join(notes[:5])}{' ...' if len(notes) > 5 else ''}")
        if any(n.startswith("errors:") for n in notes):
            total_errors += 1

    if total_targets == 0 and not args.allow_empty:
        print("NO-GO: no EvidenceManifest targets found (checked 0)")
        return 2

    print(f"Rehashed manifests changed: {total_changed}/{total_targets}")
    if total_errors:
        print(f"NO-GO: {total_errors} target(s) had errors")
        return 2
    return 0


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Unified rehash entrypoint")
    ap.add_argument(
        "cmd",
        choices=[
            "sha256-txt",
            "evidence-manifest",
            "required-reports",
            "protocol-pack",
            "fixtures-protocol-pack",
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
        if ns.cmd == "required-reports":
            return _cmd_required_reports(rest)
        if ns.cmd == "protocol-pack":
            return _cmd_protocol_pack(rest)
        if ns.cmd == "fixtures-protocol-pack":
            return _cmd_fixtures_protocol_pack(rest)

        raise _UserInputError(f"Unknown command: {ns.cmd}")
    except _UserInputError as e:
        print(f"NO-GO: {e}")
        return 2
    except json.JSONDecodeError as e:
        print(f"NO-GO: JSON parse error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
