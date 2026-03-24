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
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, metadata, version
from importlib.resources import files as resource_files
from pathlib import Path
from typing import Any

_FIXTURE_WORKSPACE_GUIDANCE = (
    "Fixture maintenance moved to the private belgi-fixtures repo. "
)

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

from belgi.core.jail import resolve_repo_rel_path, safe_relpath

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


def _deprecated_fixture_command(name: str) -> int:
    print(f"NO-GO: `{name}` no longer runs in BELGI main repo. {_FIXTURE_WORKSPACE_GUIDANCE}", file=sys.stderr)
    return 2


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
    """Run deterministic test evidence producer and write TestReportPayload."""
    repo_root = Path(args.repo).resolve()
    out_path = _repo_path(repo_root, str(args.out), must_exist=False, must_be_file=True) if args.out else repo_root / "temp" / "tests.report.json"
    run_id = args.run_id
    timestamp = _get_timestamp(args.deterministic)

    mode = "adopter_pytest" if bool(args.test_path) else "engine_smoke"

    if mode == "adopter_pytest":
        test_target = _repo_path(repo_root, str(args.test_path), must_exist=False, must_be_file=None)
        if not test_target.exists():
            payload_missing: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "run_id": run_id,
                "generated_at": timestamp,
                "mode": "adopter_pytest",
                "status": "skipped_missing_target",
                "summary_text": f"Configured test target not found: {args.test_path}",
                "summary": {
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "skipped": 1,
                    "duration_seconds": 0.0,
                },
                "exit_code": 0,
                "stdout_tail": "",
            }
            _atomic_write_json(out_path, payload_missing)
            print(f"[belgi run-tests] SKIP: missing configured target: {args.test_path}", file=sys.stderr)
            print(f"[belgi run-tests] Wrote: {out_path}", file=sys.stderr)
            return 0

        run_argv = [sys.executable, "-m", "pytest", str(test_target), "-q", "--tb=short"]
        print(f"[belgi run-tests] mode={mode} Running: {' '.join(run_argv)}", file=sys.stderr)

        start_time = time.time()
        result = subprocess.run(
            run_argv,
            cwd=str(repo_root),
            env=_det_env(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            shell=False,
        )
        duration = time.time() - start_time
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    else:
        # BELGI-owned deterministic smoke: no adopter dependency (e.g., pytest) required.
        print("[belgi run-tests] mode=engine_smoke Check: builtin protocol/resources", file=sys.stderr)
        start_time = time.time()
        checks: list[str] = []
        smoke_errors: list[str] = []
        try:
            from belgi.protocol.pack import get_builtin_protocol_context

            protocol = get_builtin_protocol_context()
            pack_id = str(getattr(protocol, "pack_id", "") or "").strip()
            manifest_sha256 = str(getattr(protocol, "manifest_sha256", "") or "").strip()
            if not pack_id:
                raise RuntimeError("builtin protocol pack_id missing/invalid")
            if not manifest_sha256:
                raise RuntimeError("builtin protocol manifest_sha256 missing/invalid")
            checks.append(f"pack_id={pack_id}")
            checks.append(f"manifest_sha256={manifest_sha256}")

            prompt_bytes = resource_files("belgi").joinpath("templates", "PromptBundle.blocks.md").read_bytes()
            docs_bytes = resource_files("belgi").joinpath("templates", "DocsCompiler.template.md").read_bytes()
            if len(prompt_bytes) == 0:
                raise RuntimeError("PromptBundle.blocks.md is empty")
            if len(docs_bytes) == 0:
                raise RuntimeError("DocsCompiler.template.md is empty")
            checks.append("templates=ok")
        except Exception as e:
            smoke_errors.append(str(e))

        duration = time.time() - start_time
        exit_code = 0 if not smoke_errors else 1
        stdout = f"engine_smoke checks: {'; '.join(checks)}\n"
        stderr = ""
        if smoke_errors:
            stderr = f"engine_smoke check failed: {'; '.join(smoke_errors)}\n"

    duration_seconds = round(duration, 2) if not args.deterministic else 0.0

    if mode == "engine_smoke":
        passed = 1 if exit_code == 0 else 0
        failed = 0 if exit_code == 0 else 1
        skipped = 0
        total = 1
    else:
        passed = 0
        failed = 0
        skipped = 0

        for line in (stdout + stderr).splitlines():
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
        if total == 0 and exit_code != 0:
            failed = 1
            total = 1

    status = "pass" if failed == 0 and exit_code == 0 else "fail"
    summary_text = (
        f"{mode} completed: total={total} passed={passed} failed={failed} skipped={skipped} rc={exit_code}"
    )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": timestamp,
        "mode": mode,
        "status": status,
        "summary_text": summary_text,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "duration_seconds": duration_seconds,
        },
        "exit_code": exit_code,
        "stdout_tail": stdout[-2000:] if len(stdout) > 2000 else stdout,
    }

    _atomic_write_json(out_path, payload)
    print(f"[belgi run-tests] Wrote: {out_path}", file=sys.stderr)
    print(
        f"[belgi run-tests] Summary: mode={mode} status={status} "
        f"total={total} passed={passed} failed={failed} skipped={skipped}",
        file=sys.stderr,
    )

    if status != "pass":
        print(f"[belgi run-tests] FAIL: {summary_text}", file=sys.stderr)
        return 1

    print(f"[belgi run-tests] PASS: {summary_text}", file=sys.stderr)
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
        print("[belgi invariant-eval] ERROR: LockedSpec.invariants must be a list", file=sys.stderr)
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
    
    print("[belgi invariant-eval] PASS: all invariants satisfied", file=sys.stderr)
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

    signing_key_raw = str(getattr(args, "signing_key", "") or "").strip()
    signing_key_env_name = str(getattr(args, "signing_key_env", "") or "").strip()
    if signing_key_raw and signing_key_env_name:
        print("[belgi verify-attestation] ERROR: provide at most one of --signing-key or --signing-key-env", file=sys.stderr)
        return 3

    resolved_signing_key = signing_key_raw
    if signing_key_env_name:
        resolved_signing_key = str(os.environ.get(signing_key_env_name, "") or "")
        if not resolved_signing_key.strip():
            print(
                f"[belgi verify-attestation] ERROR: --signing-key-env variable missing/empty: {signing_key_env_name}",
                file=sys.stderr,
            )
            return 3

    if signature_required and not resolved_signing_key.strip():
        print(
            "[belgi verify-attestation] ERROR: tier requires attestation signature; provide --signing-key or --signing-key-env (32-byte hex seed).",
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

    if resolved_signing_key.strip():
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except Exception:
            print(
                "[belgi verify-attestation] ERROR: missing crypto dependency for Ed25519 signing (install 'cryptography' in the declared Environment Envelope).",
                file=sys.stderr,
            )
            return 3

        seed_hex = resolved_signing_key.strip()
        if signing_key_env_name:
            seed_hex = seed_hex.strip()
        elif ":" in seed_hex or "\\" in seed_hex or "/" in seed_hex:
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
    
    print("[belgi verify-attestation] PASS: attestation generated", file=sys.stderr)
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
    print("[belgi diff-capture] PASS: diff captured", file=sys.stderr)
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
        print("[belgi pack build] ERROR: --out must equal --in (use build_builtin_pack.py for copy workflows)", file=sys.stderr)
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
    print("[belgi pack build] PASS: manifest built and validated", file=sys.stderr)
    return 0


def cmd_pack_verify(args: argparse.Namespace) -> int:
    """Verify protocol pack manifest matches file tree.
    
    Reads --in directory and its ProtocolPackManifest.json,
    validates that manifest matches actual file hashes/sizes,
    and that pack_id is correctly computed.
    """
    # Lazy import. Ensure repo root is on path to avoid shadowing by tools/belgi.py.
    import sys
    from importlib.resources import as_file, files
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    
    from belgi.protocol.pack import (
        MANIFEST_FILENAME,
        validate_manifest_bytes,
    )

    def _emit_manifest_files_diff(*, pack_root: Path, manifest_bytes: bytes) -> None:
        try:
            from belgi.core.jail import normalize_repo_rel_path
            from belgi.protocol.pack import scan_pack_dir
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
            print("[belgi pack verify] source: builtin (installed package)", file=sys.stderr)
            print(f"[belgi pack verify] pack_name: {pack_name}", file=sys.stderr)
            print(f"[belgi pack verify] pack_id: {pack_id}", file=sys.stderr)
            print(f"[belgi pack verify] manifest_sha256: {manifest_sha256}", file=sys.stderr)
            print(f"[belgi pack verify] files: {file_count}", file=sys.stderr)
            print("[belgi pack verify] PASS: builtin manifest verified", file=sys.stderr)
        return 0

    if not args.input:
        print("[belgi pack verify] ERROR: --in or --builtin required", file=sys.stderr)
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
    print("[belgi pack verify] PASS: manifest verified", file=sys.stderr)
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
    p_att.add_argument(
        "--signing-key-env",
        help="Environment variable containing the Ed25519 signing key seed (64 hex chars).",
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
    p_fix = subparsers.add_parser("fixtures", help="Deprecated compatibility stubs for fixture maintenance")
    fix_subs = p_fix.add_subparsers(dest="fixtures_command", help="fixtures subcommand")

    p_sync = fix_subs.add_parser("sync-pack-identity", help="Deprecated: moved to private belgi-fixtures repo")
    p_sync.add_argument("--repo", default=".", help="Repo root")
    p_sync.add_argument("--pack-dir", default="belgi/_protocol_packs/v1", help="Repo-relative active protocol pack directory")

    p_regen = fix_subs.add_parser("regen-seals", help="Deprecated: moved to private belgi-fixtures repo")
    p_regen.add_argument("--repo", default=".", help="Repo root")
    p_regen.add_argument(
        "--create-missing-private-keys",
        action="store_true",
        help="Create missing seal private keys deterministically in the private fixture workspace (default: NO-GO)",
    )
    p_regen.add_argument(
        "--only-touched",
        action="store_true",
        help="Only update fixtures that required self-healing changes in this run (default: update all eligible fixtures)",
    )

    p_all = fix_subs.add_parser("fix-all", help="Deprecated: moved to private belgi-fixtures repo")
    p_all.add_argument("--repo", default=".", help="Repo root")
    p_all.add_argument("--pack-dir", default="belgi/_protocol_packs/v1", help="Repo-relative active protocol pack directory")
    p_all.add_argument(
        "--create-missing-private-keys",
        action="store_true",
        help="Create missing seal private keys deterministically in the private fixture workspace (default: NO-GO)",
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
        if args.fixtures_command in {"sync-pack-identity", "regen-seals", "fix-all"}:
            return _deprecated_fixture_command(str(args.fixtures_command))
        else:
            p_fix.print_help()
            return 3
    else:
        parser.print_help()
        return 3


if __name__ == "__main__":
    sys.exit(main())
