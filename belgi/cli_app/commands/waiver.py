from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import belgi.cli_app.commands.run as run_commands


def _waiver_schema() -> dict[str, object]:
    from belgi.protocol.pack import get_builtin_protocol_context

    protocol = get_builtin_protocol_context()
    schema_obj = protocol.read_json("schemas/Waiver.schema.json")
    if not isinstance(schema_obj, dict):
        raise ValueError("builtin Waiver.schema.json must be a JSON object")
    return schema_obj

def _assert_valid_waiver_doc(*, waiver_obj: object, label: str) -> dict[str, object]:
    from belgi.core.schema import validate_schema

    if not isinstance(waiver_obj, dict):
        raise ValueError(f"{label} must be a JSON object")
    schema_obj = _waiver_schema()
    errors = validate_schema(waiver_obj, schema_obj, root_schema=schema_obj, path=label)
    if errors:
        first = errors[0]
        err_path = str(first.path or label)
        msg = str(first.message or "schema validation failed")
        raise ValueError(f"{label} invalid: {err_path}: {msg}")
    return waiver_obj

def cmd_waiver_new(args: argparse.Namespace) -> int:
    from belgi.core.jail import resolve_repo_rel_path, safe_relpath

    repo_root = Path(str(args.repo)).resolve()
    if not repo_root.exists():
        print(f"[belgi waiver new] ERROR: repo path does not exist: {repo_root}", file=sys.stderr)
        return 3
    if not repo_root.is_dir():
        print(f"[belgi waiver new] ERROR: repo path is not a directory: {repo_root}", file=sys.stderr)
        return 3
    if repo_root.is_symlink():
        print(f"[belgi waiver new] ERROR: symlink repo root not allowed: {repo_root}", file=sys.stderr)
        return 3

    try:
        workspace_rel, workspace_dir = run_commands._resolve_workspace_dir(
            repo_root,
            getattr(args, "workspace", run_commands.DEFAULT_WORKSPACE_REL),
            must_exist=True,
        )
        run_commands._migrate_legacy_run_key_dirs(
            workspace_runs_dir=workspace_dir / "runs",
            store_runs_dir=run_commands._resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=False),
            repo_root=repo_root,
        )
        run_id = run_commands._validate_run_id(str(args.run_id))
        gate_id = str(getattr(args, "gate", "") or "").strip().upper()
        if gate_id not in ("Q", "R"):
            raise ValueError("--gate must be Q or R")
        rule_id = str(getattr(args, "rule_id", "") or "").strip()
        if not rule_id:
            raise ValueError("--rule-id missing/invalid")
        waiver_id = run_commands._validate_waiver_id(str(args.waiver_id))
        expires_at = str(getattr(args, "expires_at", "") or "").strip()
        if not run_commands._RFC3339_UTC_RE.fullmatch(expires_at):
            raise ValueError("--expires-at must be RFC3339 (e.g. 2100-01-01T00:00:00Z)")
        run_dir = run_commands._resolve_run_dir(repo_root=repo_root, workspace_rel=workspace_rel, run_id=run_id, must_exist=True)

        out_arg = str(getattr(args, "out", "") or "").strip()
        if out_arg:
            waiver_path = resolve_repo_rel_path(
                repo_root,
                out_arg,
                must_exist=False,
                must_be_file=None,
                allow_backslashes=False,
                forbid_symlinks=True,
            )
        else:
            waiver_path = run_commands._run_waivers_dir(run_dir) / f"{waiver_id}.json"

        if waiver_path.exists() and not bool(getattr(args, "force", False)):
            raise ValueError(f"waiver output already exists: {safe_relpath(repo_root, waiver_path)} (rerun with --force)")

        waiver_obj = {
            "schema_version": "1.0.0",
            "waiver_id": waiver_id,
            "gate_id": gate_id,
            "rule_id": rule_id,
            "scope": "path:TODO",
            "justification": "TODO: human-authored waiver justification",
            "mitigation": "TODO: deterministic mitigation and sunset plan",
            "approver": "human:TODO",
            "created_at": "1970-01-01T00:00:00Z",
            "expires_at": expires_at,
            "audit_trail_ref": {"id": "audit-001", "storage_ref": "waivers/audit.log"},
            "status": "revoked",
        }
        _assert_valid_waiver_doc(waiver_obj=waiver_obj, label="waiver")
        run_commands._write_json(waiver_path, waiver_obj)
    except Exception as e:
        print(f"[belgi waiver new] ERROR: {e}", file=sys.stderr)
        return 3

    print(f"[belgi waiver new] run_id: {run_id}", file=sys.stderr)
    print(f"[belgi waiver new] created: {safe_relpath(repo_root, waiver_path)}", file=sys.stderr)
    print(f"[belgi waiver new] open: {waiver_path.resolve()}", file=sys.stderr)
    print(
        f"[belgi waiver new] reminder: strict match rule_id={rule_id} scope=path:<repo-rel-path> expires_at={expires_at}",
        file=sys.stderr,
    )
    print(
        "[belgi waiver new] reminder: draft defaults to status=revoked; "
        "set status=active and replace placeholder fields before apply",
        file=sys.stderr,
    )
    return 0

def cmd_waiver_apply(args: argparse.Namespace) -> int:
    from belgi.core.jail import resolve_repo_rel_path, safe_relpath

    repo_root = Path(str(args.repo)).resolve()
    if not repo_root.exists():
        print(f"[belgi waiver apply] ERROR: repo path does not exist: {repo_root}", file=sys.stderr)
        return 3
    if not repo_root.is_dir():
        print(f"[belgi waiver apply] ERROR: repo path is not a directory: {repo_root}", file=sys.stderr)
        return 3
    if repo_root.is_symlink():
        print(f"[belgi waiver apply] ERROR: symlink repo root not allowed: {repo_root}", file=sys.stderr)
        return 3

    try:
        workspace_rel, workspace_dir = run_commands._resolve_workspace_dir(
            repo_root,
            getattr(args, "workspace", run_commands.DEFAULT_WORKSPACE_REL),
            must_exist=True,
        )
        run_commands._migrate_legacy_run_key_dirs(
            workspace_runs_dir=workspace_dir / "runs",
            store_runs_dir=run_commands._resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=False),
            repo_root=repo_root,
        )
        run_id = run_commands._validate_run_id(str(args.run_id))
        run_dir = run_commands._resolve_run_dir(repo_root=repo_root, workspace_rel=workspace_rel, run_id=run_id, must_exist=True)
        waiver_path = resolve_repo_rel_path(
            repo_root,
            str(args.waiver),
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        waiver_rel = safe_relpath(repo_root, waiver_path)
        waiver_obj = json.loads(waiver_path.read_text(encoding="utf-8", errors="strict"))
        _assert_valid_waiver_doc(waiver_obj=waiver_obj, label=f"waiver:{waiver_rel}")
        applied_path = run_commands._run_waivers_applied_path(run_dir)
        existed = applied_path.exists()
        refs = run_commands._load_run_waivers_applied_refs(repo_root=repo_root, run_dir=run_dir, run_id=run_id)
        if waiver_rel not in refs:
            refs.append(waiver_rel)
        run_commands._write_json(applied_path, run_commands._render_run_waivers_applied_doc(run_id=run_id, waivers=refs))
    except Exception as e:
        print(f"[belgi waiver apply] ERROR: {e}", file=sys.stderr)
        return 3

    print(f"[belgi waiver apply] run_id: {run_id}", file=sys.stderr)
    print(f"[belgi waiver apply] waiver: {waiver_rel}", file=sys.stderr)
    print(
        f"[belgi waiver apply] {'updated' if existed else 'created'}: {safe_relpath(repo_root, applied_path)}",
        file=sys.stderr,
    )
    gate_id = str(waiver_obj.get("gate_id") or "").strip()
    rule_id = str(waiver_obj.get("rule_id") or "").strip()
    scope = str(waiver_obj.get("scope") or "").strip()
    expires_at = str(waiver_obj.get("expires_at") or "").strip()
    print(f"[belgi waiver apply] open: {waiver_path.resolve()}", file=sys.stderr)
    print(
        (
            "[belgi waiver apply] reminder: "
            f"strict match gate={gate_id} rule_id={rule_id} scope={scope} expires_at={expires_at}"
        ),
        file=sys.stderr,
    )
    print(
        f"[belgi waiver apply] next: belgi run --repo . --tier tier-1 --intent-spec {safe_relpath(repo_root, run_commands._run_intent_path(run_dir))} --base-revision <SHA40>",
        file=sys.stderr,
    )
    return 0
