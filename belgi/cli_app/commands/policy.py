from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def cmd_supplychain_scan(args: argparse.Namespace) -> int:
    from belgi.commands.supplychain_scan import run_supplychain_scan
    try:
        return run_supplychain_scan(
            repo=Path(args.repo),
            evaluated_revision=str(args.evaluated_revision),
            out_path=Path(args.out),
            deterministic=bool(args.deterministic),
            run_id=str(getattr(args, "run_id", "unknown") or "unknown"),
        )
    except Exception as e:
        print(f"[belgi supplychain-scan] ERROR: {e}", file=sys.stderr)
        print("[belgi supplychain-scan] Remediation: Do ensure git is available and --repo is a valid git repository, then re-run supplychain-scan.", file=sys.stderr)
        return 3

def cmd_adversarial_scan(args: argparse.Namespace) -> int:
    from belgi.commands.adversarial_scan import run_adversarial_scan
    try:
        return run_adversarial_scan(
            repo=Path(args.repo),
            out_path=Path(args.out),
            deterministic=bool(args.deterministic),
            run_id=str(getattr(args, "run_id", "unknown") or "unknown"),
        )
    except Exception as e:
        print(f"[belgi adversarial-scan] ERROR: {e}", file=sys.stderr)
        print("[belgi adversarial-scan] Remediation: Do ensure the repo is readable and Python sources can be parsed, then re-run adversarial-scan.", file=sys.stderr)
        return 3

def cmd_policy_stub(args: argparse.Namespace) -> int:
    from belgi.commands.policy_stub import DEFAULT_GENERATED_AT, write_policy_stub
    from belgi.core.hash import sha256_bytes

    try:
        out_path = Path(str(args.out))
        check_ids = [str(x) for x in (args.check_id or [])]
        data = write_policy_stub(
            out_path=out_path,
            run_id=str(args.run_id),
            check_ids=check_ids,
            generated_at=str(getattr(args, "generated_at", DEFAULT_GENERATED_AT)),
        )
    except Exception as e:
        print(f"[belgi policy stub] ERROR: {e}", file=sys.stderr)
        return 3

    print(f"[belgi policy stub] wrote: {out_path}", file=sys.stderr)
    print(f"[belgi policy stub] sha256: {sha256_bytes(data)}", file=sys.stderr)
    return 0


def cmd_policy_check_overlay(args: argparse.Namespace) -> int:
    from belgi.adopter_overlay import (
        DOMAIN_PACK_MANIFEST_FILENAME,
        evaluate_overlay_requirements,
    )
    from belgi.core.jail import resolve_repo_rel_path, safe_relpath
    from belgi.protocol.pack import get_builtin_protocol_context

    try:
        repo_root = Path(str(args.repo)).resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            print(f"[belgi policy check-overlay] ERROR: invalid repo root: {repo_root}", file=sys.stderr)
            return 3
        if repo_root.is_symlink():
            print(f"[belgi policy check-overlay] ERROR: symlink repo root not allowed: {repo_root}", file=sys.stderr)
            return 3

        evidence_path = resolve_repo_rel_path(
            repo_root,
            str(args.evidence_manifest),
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        evidence_obj = json.loads(evidence_path.read_text(encoding="utf-8", errors="strict"))
        if not isinstance(evidence_obj, dict):
            raise ValueError("evidence manifest must be a JSON object")

        overlay_arg = str(args.overlay)
        overlay_manifest_path: Path
        try:
            overlay_dir = resolve_repo_rel_path(
                repo_root,
                overlay_arg,
                must_exist=True,
                must_be_file=False,
                allow_backslashes=False,
                forbid_symlinks=True,
            )
            if overlay_dir.is_dir():
                overlay_manifest_path = resolve_repo_rel_path(
                    repo_root,
                    (Path(overlay_arg) / DOMAIN_PACK_MANIFEST_FILENAME).as_posix(),
                    must_exist=True,
                    must_be_file=True,
                    allow_backslashes=False,
                    forbid_symlinks=True,
                )
            else:
                overlay_manifest_path = resolve_repo_rel_path(
                    repo_root,
                    overlay_arg,
                    must_exist=True,
                    must_be_file=True,
                    allow_backslashes=False,
                    forbid_symlinks=True,
                )
        except Exception:
            overlay_manifest_path = resolve_repo_rel_path(
                repo_root,
                overlay_arg,
                must_exist=True,
                must_be_file=True,
                allow_backslashes=False,
                forbid_symlinks=True,
            )

        protocol = get_builtin_protocol_context()
        policy_schema = protocol.read_json("schemas/PolicyReportPayload.schema.json")
        if not isinstance(policy_schema, dict):
            raise ValueError("PolicyReportPayload schema must be a JSON object")

        failure = evaluate_overlay_requirements(
            overlay_manifest_path=overlay_manifest_path,
            repo_root=repo_root,
            active_pack_name=protocol.pack_name,
            active_pack_id=protocol.pack_id,
            active_manifest_sha256=protocol.manifest_sha256,
            evidence_manifest=evidence_obj,
            policy_payload_schema=policy_schema,
        )
        if failure is not None:
            print(
                f"[belgi policy check-overlay] NO-GO: {failure.reason}: {failure.message}",
                file=sys.stderr,
            )
            print(
                "[belgi policy check-overlay] pointers: "
                f"{safe_relpath(repo_root, overlay_manifest_path)}, "
                f"{safe_relpath(repo_root, evidence_path)}",
                file=sys.stderr,
            )
            return 2

        print("[belgi policy check-overlay] GO: overlay requirements satisfied", file=sys.stderr)
        print(
            "[belgi policy check-overlay] pointers: "
            f"{safe_relpath(repo_root, overlay_manifest_path)}, "
            f"{safe_relpath(repo_root, evidence_path)}",
            file=sys.stderr,
        )
        return 0
    except Exception as e:
        print(f"[belgi policy check-overlay] ERROR: {e}", file=sys.stderr)
        return 3
