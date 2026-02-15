#!/usr/bin/env python3
"""BELGI CLI — Protocol pack management and evidence generation tools.

This is the installable CLI entrypoint (console_scripts).

Subcommands:
- belgi init           → Initialize adopter overlay defaults in a repo
- belgi policy stub    → Generate deterministic PolicyReportPayload stubs
- belgi run new        → Create deterministic adopter run workspace
- belgi run --tier     → Create deterministic run attempt under run_key/attempt_id
- belgi verify         → Verify deterministic run summaries/manifests
- belgi manifest add   → Deterministically add/update EvidenceManifest artifacts
- belgi pack build     → Build/update protocol pack manifest deterministically
- belgi pack verify    → Verify protocol pack manifest matches file tree
- belgi bundle check   → Check an evidence bundle (demo-grade checker, --demo required)
- belgi about          → Print package identity info

Exit codes:
- 0: GO
- 10: NO-GO (policy/evidence/contract failure)
- 20: USER_ERROR
- 30: INTERNAL_ERROR
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import re
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, metadata, version
from importlib.resources import as_file, files
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

from belgi.core.run_orchestrator import (
    CHAIN_OUT_DIRNAME,
    CHAIN_REPO_DIRNAME,
    orchestrate_chain_run,
    render_default_intent_spec,
)


ABOUT_PHILOSOPHY = '"Hayatta en hakiki mürşit ilimdir." (M.K. Atatürk)'
ABOUT_DEDICATION = "Bilge (8)"
ABOUT_REPO_URL = "https://github.com/belgi-protocol/belgi"
DEFAULT_WORKSPACE_REL = ".belgi"
RUN_SUMMARY_FILENAME = "run.summary.json"
ATTEMPT_ID_PATTERN = re.compile(r"^attempt-(\d+)$")
ALLOWED_RUN_TIERS = {"tier-0", "tier-1"}
RC_GO = 0
RC_NO_GO = 10
RC_USER_ERROR = 20
RC_INTERNAL_ERROR = 30


class _UserInputError(ValueError):
    """User-facing input/configuration issue (mapped to RC_USER_ERROR)."""


def _emit_machine_result(
    *,
    ok: bool,
    verdict: str,
    primary_reason: str,
    tier_id: str | None,
    run_key: str | None,
    attempt_id: str | None,
) -> None:
    payload = {
        "ok": bool(ok),
        "verdict": verdict,
        "primary_reason": str(primary_reason),
        "tier_id": tier_id,
        "run_key": run_key,
        "attempt_id": attempt_id,
    }
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


# ---------------------------------------------------------------------------
# supply-chain subcommand
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# adversarial-scan subcommand
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# policy subcommands
# ---------------------------------------------------------------------------

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
    from belgi.adopter_overlay import DOMAIN_PACK_MANIFEST_FILENAME, evaluate_overlay_requirements
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
    print(f"Philosophy: {ABOUT_PHILOSOPHY}")
    print(f"Dedication: {ABOUT_DEDICATION}")
    print(f"Repo: {ABOUT_REPO_URL}")
    return 0


# ---------------------------------------------------------------------------
# shared helpers (workspace + run metadata)
# ---------------------------------------------------------------------------

def _package_version() -> str:
    try:
        return version("belgi")
    except PackageNotFoundError:
        return "0.0.0"


def _repo_head_sha(repo_root: Path) -> str:
    try:
        cp = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as e:
        raise ValueError(
            "cannot determine repo HEAD SHA; ensure --repo is a git repository with at least one commit"
        ) from e
    sha = cp.stdout.strip()
    if len(sha) == 40 and all(c in "0123456789abcdefABCDEF" for c in sha):
        return sha.lower()
    raise ValueError("cannot determine repo HEAD SHA; `git rev-parse HEAD` returned an invalid value")


def _validate_tier_id(raw: str) -> str:
    tier_id = str(raw or "").strip()
    if tier_id not in ALLOWED_RUN_TIERS:
        raise ValueError("--tier must be one of: tier-0, tier-1")
    return tier_id


def _normalize_workspace_rel(raw: str | None) -> str:
    from belgi.core.jail import normalize_repo_rel

    ws_raw = str(raw).strip() if raw is not None else DEFAULT_WORKSPACE_REL
    if not ws_raw:
        ws_raw = DEFAULT_WORKSPACE_REL
    rel = normalize_repo_rel(ws_raw, allow_backslashes=False)
    if rel == ".":
        raise ValueError("workspace path must not be repo root")
    return rel


def _resolve_workspace_dir(repo_root: Path, workspace_raw: str | None, *, must_exist: bool) -> tuple[str, Path]:
    from belgi.core.jail import resolve_repo_rel_path

    rel = _normalize_workspace_rel(workspace_raw)
    ws_dir = resolve_repo_rel_path(
        repo_root,
        rel,
        must_exist=must_exist,
        must_be_file=False,
        allow_backslashes=False,
        forbid_symlinks=True,
    )
    if ws_dir == repo_root:
        raise ValueError("workspace path must not be repo root")
    return rel, ws_dir


def _canonical_json_bytes(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8", errors="strict")


def _compute_run_key_from_preimage(preimage: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_json_bytes(preimage)).hexdigest()


def _derive_run_key_preimage(
    *,
    repo_root: Path,
    tier_id: str,
    workspace_rel: str,
    intent_source_rel: str,
    intent_spec_sha256: str,
    protocol_pack_name: str,
    protocol_pack_id: str,
    protocol_manifest_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "summary_kind": "belgi.run_key.preimage",
        "normalized_inputs": {
            "intent_spec_source": intent_source_rel,
            "tier_id": tier_id,
            "workspace_root": workspace_rel,
        },
        "intent_spec_sha256": intent_spec_sha256,
        "belgi": {
            "package_version": _package_version(),
            "repo_head_sha": _repo_head_sha(repo_root),
        },
        "protocol_pack": {
            "manifest_sha256": protocol_manifest_sha256,
            "pack_id": protocol_pack_id,
            "pack_name": protocol_pack_name,
        },
    }


def _next_attempt_id(run_key_dir: Path) -> str:
    max_seen = 0
    if not run_key_dir.exists():
        return "attempt-0001"
    if run_key_dir.is_symlink() or not run_key_dir.is_dir():
        raise ValueError(f"invalid run key directory: {run_key_dir}")
    for child in sorted(run_key_dir.iterdir(), key=lambda p: p.name):
        if child.name.startswith(".") and not child.is_symlink():
            continue
        if child.is_symlink():
            raise ValueError(f"symlink attempt directory not allowed: {child}")
        if not child.is_dir():
            continue
        m = ATTEMPT_ID_PATTERN.fullmatch(child.name)
        if m is None:
            raise ValueError(f"unexpected attempt directory name: {child.name}")
        idx = int(m.group(1))
        if idx > max_seen:
            max_seen = idx
    return f"attempt-{max_seen + 1:04d}"


def _ensure_gitignore_entries(repo_root: Path, *, entries: list[str]) -> str | None:
    if not entries:
        return None
    gitignore_path = repo_root / ".gitignore"
    normalized = [f"{e.strip('/')}/" for e in entries]
    if any(not e or e == "/" for e in normalized):
        raise ValueError("invalid .gitignore entry")

    if gitignore_path.exists():
        if gitignore_path.is_symlink() or not gitignore_path.is_file():
            raise ValueError(f"invalid .gitignore path: {gitignore_path}")
        content = gitignore_path.read_text(encoding="utf-8", errors="strict")
        lines = content.splitlines()
        existing = {line.strip() for line in lines}
        missing = [e for e in normalized if e not in existing and f"/{e}" not in existing]
        if not missing:
            return None
        out_lines = list(lines)
        if out_lines and out_lines[-1].strip():
            out_lines.append("")
        out_lines.extend(missing)
        _write_text(gitignore_path, "\n".join(out_lines) + "\n")
        return "updated"

    _write_text(gitignore_path, "".join(f"{entry}\n" for entry in normalized))
    return "created"


# ---------------------------------------------------------------------------
# init subcommand
# ---------------------------------------------------------------------------

def _write_text_if_missing(path: Path, text: str) -> bool:
    """Write a text file only when missing. Returns True if file was created."""
    if path.exists():
        if path.is_symlink():
            raise ValueError(f"symlink not allowed: {path}")
        if not path.is_file():
            raise ValueError(f"expected file path but found non-file: {path}")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="strict", newline="\n")
    return True


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="strict", newline="\n")


def _read_builtin_intent_template_text() -> str:
    node = files("belgi").joinpath("templates", "IntentSpec.core.template.md")
    with as_file(node) as p:
        return Path(p).read_text(encoding="utf-8", errors="strict")


def _parse_quoted_toml_string(raw: str, *, label: str) -> str:
    s = raw.strip()
    if len(s) < 2 or not (s.startswith('"') and s.endswith('"')):
        raise ValueError(f"{label} must be a quoted TOML string")
    # Minimal parser for init-owned fields; escape decoding is intentionally strict.
    inner = s[1:-1]
    if '"' in inner:
        raise ValueError(f"{label} contains invalid quote content")
    return inner


def _parse_protocol_pin_from_adopter_toml(text: str) -> dict[str, str]:
    in_pin = False
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_pin = line == "[protocol_pack_pin]"
            continue
        if not in_pin or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        if key not in ("pack_name", "pack_id", "manifest_sha256"):
            continue
        values[key] = _parse_quoted_toml_string(value, label=f"protocol_pack_pin.{key}")

    missing = [k for k in ("pack_name", "pack_id", "manifest_sha256") if k not in values]
    if missing:
        raise ValueError(f"adopter.toml protocol_pack_pin missing keys: {', '.join(missing)}")
    return values


def _render_adopter_toml(
    *,
    pack_name: str,
    pack_id: str,
    manifest_sha256: str,
    workspace_rel: str,
) -> str:
    run_workspace_root = f"{workspace_rel}/runs"
    intent_template = f"{workspace_rel}/templates/IntentSpec.core.template.md"
    return (
        "# BELGI adopter defaults (one-time initialization)\n"
        "# This file is NOT per-run state. Do not mutate it during runs.\n"
        "format_version = 1\n"
        f"run_workspace_root = \"{run_workspace_root}\"\n"
        f"intent_template = \"{intent_template}\"\n"
        "default_tier_id = \"tier-0\"\n"
        "\n"
        "[protocol_pack_pin]\n"
        f"pack_name = \"{pack_name}\"\n"
        f"pack_id = \"{pack_id}\"\n"
        f"manifest_sha256 = \"{manifest_sha256}\"\n"
        "\n"
        "[overlay]\n"
        "manifest = \"belgi_pack/DomainPackManifest.json\"\n"
    )


def _render_adopter_readme(*, workspace_rel: str) -> str:
    run_root = f"{workspace_rel}/runs"
    return (
        "# BELGI Local Layout\n\n"
        f"- `{workspace_rel}/adopter.toml`: one-time defaults for this repository (not per-run state)\n"
        f"- `{workspace_rel}/templates/IntentSpec.core.template.md`: local template copied from BELGI package at init time\n"
        f"- `{run_root}/<run_key>/<attempt_id>/`: run-local workspace (authoritative per-run files)\n"
        "- `belgi_pack/DomainPackManifest.json`: adopter-owned overlay checks for optional strict verification\n\n"
        "Rules:\n"
        "- Do not copy BELGI canonicals (`schemas/`, `gates/`, `tiers/`) into this repository.\n"
        f"- Keep per-run files under `{run_root}/<run_key>/<attempt_id>/` and freeze them into LockedSpec/evidence artifacts.\n"
    )


def _render_domain_pack_manifest_stub(*, pack_name: str, pack_id: str, manifest_sha256: str) -> str:
    obj = {
        "format_version": 1,
        "pack_name": "adopter-overlay",
        "pack_semver": "0.1.0",
        "belgi_protocol_pack_pin": {
            "pack_name": pack_name,
            "pack_id": pack_id,
            "manifest_sha256": manifest_sha256,
        },
        "required_policy_check_ids": [],
    }
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize BELGI adopter defaults (idempotent, no canonical copies)."""
    from belgi.protocol.pack import get_builtin_protocol_context

    repo_root = Path(str(args.repo)).resolve()
    if not repo_root.exists():
        print(f"[belgi init] ERROR: repo path does not exist: {repo_root}", file=sys.stderr)
        return 3
    if not repo_root.is_dir():
        print(f"[belgi init] ERROR: repo path is not a directory: {repo_root}", file=sys.stderr)
        return 3
    if repo_root.is_symlink():
        print(f"[belgi init] ERROR: symlink repo root not allowed: {repo_root}", file=sys.stderr)
        return 3

    try:
        workspace_rel, workspace_dir = _resolve_workspace_dir(
            repo_root,
            getattr(args, "workspace", DEFAULT_WORKSPACE_REL),
            must_exist=False,
        )
    except Exception as e:
        print(f"[belgi init] ERROR: invalid workspace path: {e}", file=sys.stderr)
        return 3

    try:
        protocol = get_builtin_protocol_context()
    except Exception as e:
        print(f"[belgi init] ERROR: cannot load builtin protocol pack identity: {e}", file=sys.stderr)
        return 3

    adopter_dir = workspace_dir
    runs_dir = adopter_dir / "runs"
    cache_dir = adopter_dir / "cache"
    config_dir = adopter_dir / "config"
    overlay_dir = repo_root / "belgi_pack"
    templates_dir = adopter_dir / "templates"
    adopter_toml_path = adopter_dir / "adopter.toml"
    adopter_readme_path = adopter_dir / "README.md"
    overlay_manifest_path = overlay_dir / "DomainPackManifest.json"
    intent_template_path = templates_dir / "IntentSpec.core.template.md"

    # Guard against symlink directories and conflicting file paths.
    for d in (adopter_dir, runs_dir, cache_dir, config_dir, overlay_dir, templates_dir):
        if d.exists() and not d.is_dir():
            print(f"[belgi init] ERROR: expected directory path but found non-directory: {d}", file=sys.stderr)
            return 3
        if d.exists() and d.is_symlink():
            print(f"[belgi init] ERROR: symlink directory not allowed: {d}", file=sys.stderr)
            return 3

    adopter_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    templates_dir.mkdir(parents=True, exist_ok=True)
    overlay_dir.mkdir(parents=True, exist_ok=True)

    created: list[Path] = []
    updated: list[Path] = []
    current_pin = {
        "pack_name": protocol.pack_name,
        "pack_id": protocol.pack_id,
        "manifest_sha256": protocol.manifest_sha256,
    }

    try:
        ignore_entries = [DEFAULT_WORKSPACE_REL]
        if workspace_rel != DEFAULT_WORKSPACE_REL:
            ignore_entries.append(workspace_rel)
        gitignore_state = _ensure_gitignore_entries(repo_root, entries=ignore_entries)
        if gitignore_state == "created":
            created.append(repo_root / ".gitignore")
        elif gitignore_state == "updated":
            updated.append(repo_root / ".gitignore")

        # Template provisioning for adopter repos (repo-local path).
        if _write_text_if_missing(intent_template_path, _read_builtin_intent_template_text()):
            created.append(intent_template_path)

        if adopter_toml_path.exists():
            if adopter_toml_path.is_symlink() or not adopter_toml_path.is_file():
                raise ValueError(f"invalid adopter.toml path: {adopter_toml_path}")
            existing_pin = _parse_protocol_pin_from_adopter_toml(
                adopter_toml_path.read_text(encoding="utf-8", errors="strict")
            )
            drift = existing_pin != current_pin
            if drift and not bool(getattr(args, "refresh_pin", False)):
                print("[belgi init] WARNING: adopter.toml protocol_pack_pin differs from active builtin pack.", file=sys.stderr)
                print(
                    "[belgi init] ERROR: re-run with --refresh-pin to update pins explicitly (fail-closed).",
                    file=sys.stderr,
                )
                return 1
            if drift and bool(getattr(args, "refresh_pin", False)):
                _write_text(
                    adopter_toml_path,
                    _render_adopter_toml(
                        pack_name=protocol.pack_name,
                        pack_id=protocol.pack_id,
                        manifest_sha256=protocol.manifest_sha256,
                        workspace_rel=workspace_rel,
                    ),
                )
                updated.append(adopter_toml_path)
        elif _write_text_if_missing(
            adopter_toml_path,
            _render_adopter_toml(
                pack_name=protocol.pack_name,
                pack_id=protocol.pack_id,
                manifest_sha256=protocol.manifest_sha256,
                workspace_rel=workspace_rel,
            ),
        ):
            created.append(adopter_toml_path)

        if _write_text_if_missing(adopter_readme_path, _render_adopter_readme(workspace_rel=workspace_rel)):
            created.append(adopter_readme_path)

        if overlay_manifest_path.exists():
            if overlay_manifest_path.is_symlink() or not overlay_manifest_path.is_file():
                raise ValueError(f"invalid overlay manifest path: {overlay_manifest_path}")
            if bool(getattr(args, "refresh_pin", False)):
                try:
                    overlay_obj = json.loads(overlay_manifest_path.read_text(encoding="utf-8", errors="strict"))
                except Exception as e:
                    raise ValueError(f"overlay manifest is not valid UTF-8 JSON: {e}") from e
                if not isinstance(overlay_obj, dict):
                    raise ValueError("overlay manifest must be a JSON object")
                pin = overlay_obj.get("belgi_protocol_pack_pin")
                if not isinstance(pin, dict):
                    raise ValueError("overlay manifest missing belgi_protocol_pack_pin")
                pin["pack_name"] = protocol.pack_name
                pin["pack_id"] = protocol.pack_id
                pin["manifest_sha256"] = protocol.manifest_sha256
                _write_text(
                    overlay_manifest_path,
                    json.dumps(overlay_obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                )
                updated.append(overlay_manifest_path)
        elif _write_text_if_missing(
            overlay_manifest_path,
            _render_domain_pack_manifest_stub(
                pack_name=protocol.pack_name,
                pack_id=protocol.pack_id,
                manifest_sha256=protocol.manifest_sha256,
            ),
        ):
            created.append(overlay_manifest_path)
    except Exception as e:
        print(f"[belgi init] ERROR: {e}", file=sys.stderr)
        return 3

    print(f"[belgi init] repo: {repo_root}", file=sys.stderr)
    print(f"[belgi init] workspace: {workspace_rel}", file=sys.stderr)
    print(
        f"[belgi init] protocol_pack: {protocol.pack_name} "
        f"(pack_id={protocol.pack_id}, manifest_sha256={protocol.manifest_sha256})",
        file=sys.stderr,
    )
    if created:
        for p in created:
            print(f"[belgi init] created: {p.relative_to(repo_root).as_posix()}", file=sys.stderr)
    if updated:
        for p in updated:
            print(f"[belgi init] updated: {p.relative_to(repo_root).as_posix()}", file=sys.stderr)
    if not created and not updated:
        print("[belgi init] no changes (already initialized)", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# run new subcommand
# ---------------------------------------------------------------------------

def _validate_run_id(raw: str) -> str:
    rid = str(raw or "").strip()
    if not rid:
        raise ValueError("--run-id missing/invalid")
    if "/" in rid or "\\" in rid:
        raise ValueError("--run-id must not contain path separators")
    if rid in (".", ".."):
        raise ValueError("--run-id missing/invalid")
    if ":" in rid or "\x00" in rid:
        raise ValueError("--run-id contains forbidden characters")
    return rid


def _write_json_placeholder(path: Path, *, force: bool) -> str | None:
    payload = "{}\n"
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"invalid path in run workspace: {path}")
        if not force:
            return None
        _write_text(path, payload)
        return "updated"
    _write_text(path, payload)
    return "created"


def _write_json_object(path: Path, obj: object, *, force: bool) -> str | None:
    payload = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"invalid path in run workspace: {path}")
        if not force:
            return None
        _write_text(path, payload)
        return "updated"
    _write_text(path, payload)
    return "created"


def _write_json(path: Path, obj: object) -> None:
    _write_text(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _seed_run_workspace(
    *,
    run_dir: Path,
    run_id: str,
    intent_bytes: bytes,
    force: bool,
) -> tuple[list[Path], list[Path], list[Path]]:
    intent_path = run_dir / "IntentSpec.core.md"
    placeholders = [
        run_dir / "tolerances.json",
        run_dir / "toolchain.json",
    ]
    evidence_manifest_path = run_dir / "EvidenceManifest.json"
    evidence_manifest_obj = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "artifacts": [],
        "commands_executed": [],
        "envelope_attestation": None,
    }

    created: list[Path] = []
    updated: list[Path] = []

    if intent_path.exists():
        if intent_path.is_symlink() or not intent_path.is_file():
            raise ValueError(f"invalid path in run workspace: {intent_path}")
        if force:
            intent_path.write_bytes(intent_bytes)
            updated.append(intent_path)
    else:
        intent_path.parent.mkdir(parents=True, exist_ok=True)
        intent_path.write_bytes(intent_bytes)
        created.append(intent_path)

    for path in placeholders:
        state = _write_json_placeholder(path, force=force)
        if state == "created":
            created.append(path)
        elif state == "updated":
            updated.append(path)

    manifest_state = _write_json_object(
        evidence_manifest_path,
        evidence_manifest_obj,
        force=force,
    )
    if manifest_state == "created":
        created.append(evidence_manifest_path)
    elif manifest_state == "updated":
        updated.append(evidence_manifest_path)

    seeded_paths = [intent_path, *placeholders, evidence_manifest_path]
    return created, updated, seeded_paths


def cmd_run_new(args: argparse.Namespace) -> int:
    from belgi.core.jail import safe_relpath

    repo_root = Path(str(args.repo)).resolve()
    if not repo_root.exists():
        print(f"[belgi run new] ERROR: repo path does not exist: {repo_root}", file=sys.stderr)
        return 3
    if not repo_root.is_dir():
        print(f"[belgi run new] ERROR: repo path is not a directory: {repo_root}", file=sys.stderr)
        return 3
    if repo_root.is_symlink():
        print(f"[belgi run new] ERROR: symlink repo root not allowed: {repo_root}", file=sys.stderr)
        return 3

    try:
        workspace_rel, workspace_dir = _resolve_workspace_dir(
            repo_root,
            getattr(args, "workspace", DEFAULT_WORKSPACE_REL),
            must_exist=True,
        )
        run_id = _validate_run_id(str(args.run_id))
        force = bool(getattr(args, "force", False))

        template_path = workspace_dir / "templates" / "IntentSpec.core.template.md"
        if not template_path.exists() or not template_path.is_file() or template_path.is_symlink():
            raise ValueError(
                f"missing workspace template; run `belgi init --repo . --workspace {workspace_rel}` first"
            )
        template_bytes = template_path.read_bytes()

        run_dir = workspace_dir / "runs" / run_id
        if run_dir.exists() and (run_dir.is_symlink() or not run_dir.is_dir()):
            raise ValueError(f"invalid run workspace path: {run_dir}")
        run_dir.mkdir(parents=True, exist_ok=True)

        created, updated, _ = _seed_run_workspace(
            run_dir=run_dir,
            run_id=run_id,
            intent_bytes=template_bytes,
            force=force,
        )

    except Exception as e:
        print(f"[belgi run new] ERROR: {e}", file=sys.stderr)
        return 3

    print(f"[belgi run new] repo: {repo_root}", file=sys.stderr)
    print(f"[belgi run new] workspace: {workspace_rel}", file=sys.stderr)
    print(f"[belgi run new] run_id: {run_id}", file=sys.stderr)
    if created:
        for p in created:
            print(f"[belgi run new] created: {safe_relpath(repo_root, p)}", file=sys.stderr)
    if updated:
        for p in updated:
            print(f"[belgi run new] updated: {safe_relpath(repo_root, p)}", file=sys.stderr)
    if not created and not updated:
        print("[belgi run new] no changes (already initialized)", file=sys.stderr)
    return 0


def _build_artifact_entries(repo_root: Path, *, paths: list[Path]) -> list[dict[str, str]]:
    from belgi.core.hash import sha256_bytes
    from belgi.core.jail import safe_relpath

    pairs = sorted(
        ((safe_relpath(repo_root, p), p) for p in paths),
        key=lambda x: x[0],
    )
    out: list[dict[str, str]] = []
    for rel, p in pairs:
        out.append({"path": rel, "sha256": sha256_bytes(p.read_bytes())})
    return out


def _validate_paths_within_attempt(*, attempt_dir: Path, paths: list[Path]) -> None:
    attempt_resolved = attempt_dir.resolve()
    for p in paths:
        resolved = p.resolve()
        if resolved != attempt_resolved and attempt_resolved not in resolved.parents:
            raise ValueError(f"artifact escapes attempt directory: {p}")


def cmd_run(args: argparse.Namespace) -> int:
    from belgi.core.hash import sha256_bytes
    from belgi.core.jail import resolve_repo_rel_path, safe_relpath
    from belgi.protocol.pack import get_builtin_protocol_context

    repo_root = Path(str(args.repo)).resolve()
    tier_id: str | None = str(getattr(args, "tier", "") or "").strip() or None
    run_key: str | None = None
    attempt_id: str | None = None

    try:
        if not repo_root.exists():
            raise _UserInputError(f"repo path does not exist: {repo_root}")
        if not repo_root.is_dir():
            raise _UserInputError(f"repo path is not a directory: {repo_root}")
        if repo_root.is_symlink():
            raise _UserInputError(f"symlink repo root not allowed: {repo_root}")

        try:
            tier_id = _validate_tier_id(str(getattr(args, "tier", "")))
        except ValueError as e:
            raise _UserInputError(str(e)) from e

        try:
            workspace_rel, workspace_dir = _resolve_workspace_dir(
                repo_root,
                getattr(args, "workspace", DEFAULT_WORKSPACE_REL),
                must_exist=True,
            )
        except ValueError as e:
            raise _UserInputError(str(e)) from e

        runs_dir = workspace_dir / "runs"
        if runs_dir.exists() and (runs_dir.is_symlink() or not runs_dir.is_dir()):
            raise ValueError(f"invalid runs directory: {runs_dir}")
        runs_dir.mkdir(parents=True, exist_ok=True)

        template_path = workspace_dir / "templates" / "IntentSpec.core.template.md"
        if not template_path.exists() or not template_path.is_file() or template_path.is_symlink():
            raise ValueError(
                f"missing workspace template; run `belgi init --repo . --workspace {workspace_rel}` first"
            )

        intent_spec_arg = str(getattr(args, "intent_spec", "") or "").strip()
        if intent_spec_arg:
            intent_path = resolve_repo_rel_path(
                repo_root,
                intent_spec_arg,
                must_exist=True,
                must_be_file=True,
                allow_backslashes=False,
                forbid_symlinks=True,
            )
            if intent_path.is_symlink():
                raise ValueError("intent spec symlink not allowed")
            intent_bytes = intent_path.read_bytes()
            intent_source_rel = safe_relpath(repo_root, intent_path)
        else:
            intent_bytes = render_default_intent_spec(tier_id=tier_id)
            intent_source_rel = "(auto)"

        protocol = get_builtin_protocol_context()
        repo_head_sha = _repo_head_sha(repo_root)
        preimage = _derive_run_key_preimage(
            repo_root=repo_root,
            tier_id=tier_id,
            workspace_rel=workspace_rel,
            intent_source_rel=intent_source_rel,
            intent_spec_sha256=sha256_bytes(intent_bytes),
            protocol_pack_name=protocol.pack_name,
            protocol_pack_id=protocol.pack_id,
            protocol_manifest_sha256=protocol.manifest_sha256,
        )
        run_key = _compute_run_key_from_preimage(preimage)

        run_key_dir = runs_dir / run_key
        if run_key_dir.exists() and (run_key_dir.is_symlink() or not run_key_dir.is_dir()):
            raise ValueError(f"invalid run_key directory: {run_key_dir}")
        run_key_dir.mkdir(parents=True, exist_ok=True)

        attempt_id = _next_attempt_id(run_key_dir)
        attempt_dir = run_key_dir / attempt_id
        if attempt_dir.exists():
            raise ValueError(f"attempt directory already exists: {attempt_dir}")
        attempt_dir.mkdir(parents=False, exist_ok=False)

        with contextlib.redirect_stdout(sys.stderr):
            chain_result = orchestrate_chain_run(
                source_repo_root=repo_root,
                chain_repo_dir=attempt_dir / CHAIN_REPO_DIRNAME,
                run_key=run_key,
                tier_id=tier_id,
                repo_head_sha=repo_head_sha,
                intent_bytes=intent_bytes,
                protocol=protocol,
            )
        chain_repo_dir = chain_result.chain_repo_dir
        chain_out_dir = chain_result.chain_out_dir
        chain_paths = chain_result.chain_paths
        _validate_paths_within_attempt(attempt_dir=attempt_dir, paths=chain_paths)

        summary_obj = {
            "schema_version": "1.0.0",
            "summary_kind": "belgi_run_attempt",
            "run_key": run_key,
            "attempt_id": attempt_id,
            "tier_id": tier_id,
            "workspace_root": workspace_rel,
            "run_root": safe_relpath(repo_root, run_key_dir),
            "attempt_root": safe_relpath(repo_root, attempt_dir),
            "run_key_preimage": preimage,
            "chain_repo_root": safe_relpath(repo_root, chain_repo_dir),
            "chain_output_root": safe_relpath(repo_root, chain_out_dir),
            "artifacts": _build_artifact_entries(repo_root, paths=chain_paths),
        }
        summary_path = attempt_dir / RUN_SUMMARY_FILENAME
        _write_json(summary_path, summary_obj)

    except _UserInputError as e:
        _emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=tier_id,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        print(f"[belgi run] USER_ERROR: {e}", file=sys.stderr)
        return RC_USER_ERROR
    except ValueError as e:
        _emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=tier_id,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        print(f"[belgi run] NO-GO: {e}", file=sys.stderr)
        return RC_NO_GO
    except Exception as e:
        _emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=tier_id,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        print(f"[belgi run] ERROR: {e}", file=sys.stderr)
        return RC_INTERNAL_ERROR

    _emit_machine_result(
        ok=True,
        verdict="GO",
        primary_reason="",
        tier_id=tier_id,
        run_key=run_key,
        attempt_id=attempt_id,
    )
    print(f"[belgi run] repo: {repo_root}", file=sys.stderr)
    print(f"[belgi run] workspace: {workspace_rel}", file=sys.stderr)
    print(f"[belgi run] tier: {tier_id}", file=sys.stderr)
    print(f"[belgi run] run_key: {run_key}", file=sys.stderr)
    print(f"[belgi run] attempt_id: {attempt_id}", file=sys.stderr)
    print(f"[belgi run] created: {safe_relpath(repo_root, summary_path)}", file=sys.stderr)
    print(
        f"[belgi run] created: {safe_relpath(repo_root, chain_repo_dir / chain_result.rel_evidence_final)}",
        file=sys.stderr,
    )
    print(
        f"[belgi run] created: {safe_relpath(repo_root, chain_repo_dir / chain_result.rel_seal)}",
        file=sys.stderr,
    )
    print(
        f"[belgi run] created: {safe_relpath(repo_root, chain_repo_dir / chain_result.rel_gate_s)}",
        file=sys.stderr,
    )
    return RC_GO


def _load_json_object(path: Path, *, label: str) -> dict[str, object]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception as e:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"{label} must be a JSON object")
    return obj


def _list_dirs_sorted(root: Path) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"expected directory (non-symlink): {root}")
    out: list[Path] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if child.name.startswith(".") and not child.is_symlink():
            continue
        if child.is_symlink():
            raise ValueError(f"symlink path not allowed: {child}")
        if child.is_dir():
            out.append(child)
    return out


def _discover_attempt_dirs(target: Path) -> list[Path]:
    if target.is_symlink():
        raise ValueError(f"symlink path not allowed: {target}")
    if target.is_file():
        if target.name != RUN_SUMMARY_FILENAME:
            raise ValueError("--in file path must be run.summary.json")
        return [target.parent]
    if not target.is_dir():
        raise ValueError(f"--in path is not a file or directory: {target}")

    summary_here = target / RUN_SUMMARY_FILENAME
    if summary_here.exists():
        if summary_here.is_symlink() or not summary_here.is_file():
            raise ValueError(f"invalid summary path: {summary_here}")
        return [target]

    first_level = _list_dirs_sorted(target)
    if not first_level:
        raise ValueError(f"no run attempts found under: {target}")

    direct_attempts = [d for d in first_level if (d / RUN_SUMMARY_FILENAME).is_file()]
    if direct_attempts:
        if len(direct_attempts) != len(first_level):
            raise ValueError(f"mixed directory structure under: {target}")
        return direct_attempts

    attempts: list[Path] = []
    for run_dir in first_level:
        second_level = _list_dirs_sorted(run_dir)
        if not second_level:
            raise ValueError(f"run_key directory has no attempts: {run_dir}")
        for attempt_dir in second_level:
            summary_path = attempt_dir / RUN_SUMMARY_FILENAME
            if not summary_path.exists() or summary_path.is_symlink() or not summary_path.is_file():
                raise ValueError(f"missing run summary: {summary_path}")
            attempts.append(attempt_dir)
    return attempts


def _verify_attempt_dir(repo_root: Path, attempt_dir: Path) -> tuple[str, str]:
    from belgi.core.hash import sha256_bytes
    from belgi.core.jail import resolve_repo_rel_path
    from belgi.core.schema import validate_schema
    from belgi.protocol.pack import get_builtin_protocol_context

    summary_path = attempt_dir / RUN_SUMMARY_FILENAME
    if not summary_path.exists() or summary_path.is_symlink() or not summary_path.is_file():
        raise ValueError(f"missing run summary: {summary_path}")
    summary = _load_json_object(summary_path, label=RUN_SUMMARY_FILENAME)

    run_key = str(summary.get("run_key") or "")
    attempt_id = str(summary.get("attempt_id") or "")
    if not run_key:
        raise ValueError("run.summary.json missing run_key")
    if not attempt_id:
        raise ValueError("run.summary.json missing attempt_id")
    if run_key != attempt_dir.parent.name:
        raise ValueError("run_key does not match directory layout")
    if attempt_id != attempt_dir.name:
        raise ValueError("attempt_id does not match directory layout")

    preimage = summary.get("run_key_preimage")
    if not isinstance(preimage, dict):
        raise ValueError("run.summary.json missing run_key_preimage object")
    if _compute_run_key_from_preimage(preimage) != run_key:
        raise ValueError("run_key preimage hash mismatch")

    artifacts = summary.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("run.summary.json artifacts missing/invalid")

    last_path = ""
    evidence_manifest_path: Path | None = None
    for item in artifacts:
        if not isinstance(item, dict):
            raise ValueError("run.summary.json artifacts[] entries must be objects")
        rel = item.get("path")
        declared_hash = item.get("sha256")
        if not isinstance(rel, str) or not rel:
            raise ValueError("run.summary.json artifact.path missing/invalid")
        if not isinstance(declared_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", declared_hash):
            raise ValueError("run.summary.json artifact.sha256 missing/invalid")
        if last_path and rel < last_path:
            raise ValueError("run.summary.json artifacts must be sorted by path")
        last_path = rel

        target = resolve_repo_rel_path(
            repo_root,
            rel,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        resolved_target = target.resolve()
        resolved_attempt = attempt_dir.resolve()
        if resolved_target != resolved_attempt and resolved_attempt not in resolved_target.parents:
            raise ValueError(f"artifact escapes attempt directory: {rel}")
        actual_hash = sha256_bytes(target.read_bytes())
        if actual_hash.lower() != declared_hash.lower():
            raise ValueError(f"artifact hash mismatch: {rel}")
        if target.name == "EvidenceManifest.json":
            evidence_manifest_path = target

    if evidence_manifest_path is None:
        raise ValueError("run.summary.json artifacts missing EvidenceManifest.json")

    evidence_obj = _load_json_object(evidence_manifest_path, label="EvidenceManifest.json")
    artifacts_field = evidence_obj.get("artifacts")
    if not isinstance(artifacts_field, list):
        raise ValueError("EvidenceManifest.artifacts missing/invalid")

    if artifacts_field:
        protocol = get_builtin_protocol_context()
        schema = protocol.read_json("schemas/EvidenceManifest.schema.json")
        if not isinstance(schema, dict):
            raise ValueError("EvidenceManifest schema must be a JSON object")
        errs = validate_schema(
            evidence_obj,
            schema,
            root_schema=schema,
            path="EvidenceManifest",
        )
        if errs:
            first = errs[0]
            raise ValueError(f"EvidenceManifest schema invalid at {first.path}: {first.message}")
    else:
        required = ("schema_version", "run_id", "artifacts", "commands_executed", "envelope_attestation")
        missing = [k for k in required if k not in evidence_obj]
        if missing:
            raise ValueError(f"EvidenceManifest missing required keys: {', '.join(missing)}")
        commands_executed = evidence_obj.get("commands_executed")
        if not isinstance(commands_executed, list):
            raise ValueError("EvidenceManifest.commands_executed missing/invalid")

    run_id = evidence_obj.get("run_id")
    if run_id != run_key:
        raise ValueError("EvidenceManifest.run_id does not match run_key")

    return run_key, attempt_id


def cmd_verify(args: argparse.Namespace) -> int:
    from belgi.core.jail import resolve_repo_rel_path, safe_relpath

    repo_root = Path(str(args.repo)).resolve()
    run_key: str | None = None
    attempt_id: str | None = None

    try:
        if not repo_root.exists():
            raise _UserInputError(f"repo path does not exist: {repo_root}")
        if not repo_root.is_dir():
            raise _UserInputError(f"repo path is not a directory: {repo_root}")
        if repo_root.is_symlink():
            raise _UserInputError(f"symlink repo root not allowed: {repo_root}")

        in_arg = str(getattr(args, "input", "") or "").strip()
        if in_arg:
            try:
                target = resolve_repo_rel_path(
                    repo_root,
                    in_arg,
                    must_exist=True,
                    must_be_file=None,
                    allow_backslashes=False,
                    forbid_symlinks=True,
                )
            except ValueError as e:
                raise _UserInputError(str(e)) from e
        else:
            try:
                workspace_rel, _ = _resolve_workspace_dir(
                    repo_root,
                    getattr(args, "workspace", DEFAULT_WORKSPACE_REL),
                    must_exist=True,
                )
                target = resolve_repo_rel_path(
                    repo_root,
                    f"{workspace_rel}/runs",
                    must_exist=True,
                    must_be_file=False,
                    allow_backslashes=False,
                    forbid_symlinks=True,
                )
            except ValueError as e:
                raise _UserInputError(str(e)) from e

        attempt_dirs = _discover_attempt_dirs(target)
        verified: list[str] = []
        for attempt_dir in attempt_dirs:
            cur_run_key, cur_attempt_id = _verify_attempt_dir(repo_root, attempt_dir)
            verified.append(f"{cur_run_key}/{cur_attempt_id}")
            if run_key is None and attempt_id is None:
                run_key = cur_run_key
                attempt_id = cur_attempt_id

    except _UserInputError as e:
        _emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=None,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        print(f"[belgi verify] USER_ERROR: {e}", file=sys.stderr)
        return RC_USER_ERROR
    except ValueError as e:
        _emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=None,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        print(f"[belgi verify] NO-GO: {e}", file=sys.stderr)
        return RC_NO_GO
    except Exception as e:
        _emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=None,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        print(f"[belgi verify] ERROR: {e}", file=sys.stderr)
        return RC_INTERNAL_ERROR

    _emit_machine_result(
        ok=True,
        verdict="GO",
        primary_reason="",
        tier_id=None,
        run_key=run_key,
        attempt_id=attempt_id,
    )
    for ref in verified:
        print(f"[belgi verify] GO: {ref}", file=sys.stderr)
    print(f"[belgi verify] PASS: verified {len(verified)} attempt(s)", file=sys.stderr)
    print(f"[belgi verify] source: {safe_relpath(repo_root, target)}", file=sys.stderr)
    return RC_GO


# ---------------------------------------------------------------------------
# manifest add subcommand
# ---------------------------------------------------------------------------

def cmd_manifest_add(args: argparse.Namespace) -> int:
    from belgi.core.hash import sha256_bytes
    from belgi.core.jail import normalize_repo_rel, resolve_repo_rel_path, safe_relpath
    from belgi.core.schema import validate_schema
    from belgi.protocol.pack import get_builtin_protocol_context

    try:
        repo_root = Path(str(args.repo)).resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            raise ValueError(f"invalid repo root: {repo_root}")
        if repo_root.is_symlink():
            raise ValueError(f"symlink repo root not allowed: {repo_root}")

        manifest_path = resolve_repo_rel_path(
            repo_root,
            str(args.manifest),
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        artifact_path = resolve_repo_rel_path(
            repo_root,
            str(args.artifact),
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        if artifact_path.is_symlink():
            raise ValueError("artifact path symlink not allowed")

        kind = str(args.kind or "").strip()
        artifact_id = str(args.artifact_id or "").strip()
        media_type = str(args.media_type or "").strip()
        produced_by = str(args.produced_by or "").strip()
        if not artifact_id:
            raise ValueError("--id missing/invalid")
        if not media_type:
            raise ValueError("--media-type missing/invalid")

        protocol = get_builtin_protocol_context()
        evidence_schema = protocol.read_json("schemas/EvidenceManifest.schema.json")
        if not isinstance(evidence_schema, dict):
            raise ValueError("EvidenceManifest schema must be a JSON object")

        props = (
            evidence_schema.get("properties", {})
            .get("artifacts", {})
            .get("items", {})
            .get("properties", {})
        )
        allowed_kinds = props.get("kind", {}).get("enum", [])
        allowed_produced_by = props.get("produced_by", {}).get("enum", [])
        if kind not in allowed_kinds:
            raise ValueError(
                f"--kind not allowed by EvidenceManifest schema enum: {kind!r}"
            )
        if produced_by not in allowed_produced_by:
            raise ValueError(
                f"--produced-by not allowed by EvidenceManifest schema enum: {produced_by!r}"
            )

        manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8", errors="strict"))
        if not isinstance(manifest_obj, dict):
            raise ValueError("EvidenceManifest must be a JSON object")
        artifacts = manifest_obj.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError("EvidenceManifest.artifacts missing/invalid")

        artifact_bytes = artifact_path.read_bytes()
        artifact_hash = sha256_bytes(artifact_bytes)
        storage_ref_raw = safe_relpath(repo_root, artifact_path)
        storage_ref = normalize_repo_rel(storage_ref_raw, allow_backslashes=False)
        new_artifact = {
            "kind": kind,
            "id": artifact_id,
            "hash": artifact_hash,
            "media_type": media_type,
            "storage_ref": storage_ref,
            "produced_by": produced_by,
        }

        replaced = False
        out_artifacts: list[object] = []
        for item in artifacts:
            if not isinstance(item, dict):
                out_artifacts.append(item)
                continue
            if item.get("kind") == kind and item.get("id") == artifact_id:
                if not replaced:
                    out_artifacts.append(new_artifact)
                    replaced = True
                continue
            out_artifacts.append(item)
        if not replaced:
            out_artifacts.append(new_artifact)

        manifest_obj["artifacts"] = out_artifacts
        errs = validate_schema(
            manifest_obj,
            evidence_schema,
            root_schema=evidence_schema,
            path="EvidenceManifest",
        )
        if errs:
            first = errs[0]
            raise ValueError(
                f"EvidenceManifest schema invalid after mutation at {first.path}: {first.message}"
            )

        out_data = json.dumps(manifest_obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        manifest_path.write_text(
            out_data,
            encoding="utf-8",
            errors="strict",
            newline="\n",
        )

        print(f"[belgi manifest add] manifest: {safe_relpath(repo_root, manifest_path)}", file=sys.stderr)
        print(
            f"[belgi manifest add] artifact: {kind}:{artifact_id} hash={artifact_hash}",
            file=sys.stderr,
        )
        print(f"[belgi manifest add] storage_ref: {storage_ref}", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"[belgi manifest add] ERROR: {e}", file=sys.stderr)
        return 3


# ---------------------------------------------------------------------------
# pack build subcommand
# ---------------------------------------------------------------------------

def cmd_pack_build(args: argparse.Namespace) -> int:
    """Build/update protocol pack manifest deterministically.
    
    Scans --in directory, computes file hashes/sizes, generates
    ProtocolPackManifest.json with deterministic pack_id.
    """
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


# ---------------------------------------------------------------------------
# pack verify subcommand
# ---------------------------------------------------------------------------

def cmd_pack_verify(args: argparse.Namespace) -> int:
    """Verify protocol pack manifest matches file tree.
    
    If --builtin is specified, verifies the builtin pack from installed resources.
    Otherwise, verifies the pack at --in directory.
    """
    from importlib.resources import as_file, files

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
    
    if args.builtin:
        # Verify builtin pack from installed package resources.
        # Use as_file() to get a real Path that works with validate_manifest_bytes.
        # This is robust for both filesystem and zip-based resource loaders.
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
        
        parsed = json.loads(manifest_bytes.decode("utf-8"))
        pack_id = parsed.get("pack_id", "")
        pack_name = parsed.get("pack_name", "")
        file_count = len(parsed.get("files", []))
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        
        if getattr(args, "verbose", False):
            print(f"[belgi pack verify] source: builtin (installed package)", file=sys.stderr)
            print(f"[belgi pack verify] pack_name: {pack_name}", file=sys.stderr)
            print(f"[belgi pack verify] pack_id: {pack_id}", file=sys.stderr)
            print(f"[belgi pack verify] manifest_sha256: {manifest_sha256}", file=sys.stderr)
            print(f"[belgi pack verify] files: {file_count}", file=sys.stderr)
            print(f"[belgi pack verify] PASS: builtin manifest verified", file=sys.stderr)
        return 0
    
    # Verify pack at --in directory.
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

    if getattr(args, "verbose", False):
        src = "builtin" if args.builtin else str(in_dir)
        print(f"[belgi pack verify] source: {src}", file=sys.stderr)
        print(f"[belgi pack verify] pack_name: {pack_name}", file=sys.stderr)
        print(f"[belgi pack verify] pack_id: {pack_id}", file=sys.stderr)
        print(f"[belgi pack verify] manifest_sha256: {manifest_sha256}", file=sys.stderr)
        print(f"[belgi pack verify] files: {file_count}", file=sys.stderr)
        print(f"[belgi pack verify] PASS: manifest verified", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# bundle check subcommand (demo-grade checker)
# ---------------------------------------------------------------------------

def cmd_bundle_check(args: argparse.Namespace) -> int:
    """Check an evidence bundle (demo-grade checker).
    
    This is a publish-safe checker that ONLY depends on belgi* modules.
    It checks:
    - Required bundle files exist (no symlinks)
        - Protocol identity binding: LockedSpec.protocol_pack must match the active pack
            on pack_id, pack_name, and manifest_sha256 (source is metadata)
    - Run_id consistency across all core artifacts
    - All ObjectRefs in SealManifest exist and hash-match (fail-closed)
    - GateVerdicts are all GO
    - seal_hash recomputes correctly
    
    IMPORTANT: This is a DEMO-GRADE checker. It does NOT replay Gate Q/R/S logic.
    For production verification, use the full gate verifiers (chain/gate_*_verify.py).
    
    --demo flag is REQUIRED to acknowledge this limitation.
    """
    from belgi.protocol.pack import get_builtin_protocol_context
    from belgi.core.hash import sha256_bytes, is_hex_sha256
    from chain.seal_bundle import _seal_hash as canonical_seal_hash
    
    if not args.demo:
        print("[belgi bundle check] ERROR: --demo flag required", file=sys.stderr)
        print("", file=sys.stderr)
        print("This is a DEMO-GRADE checker that does NOT replay Gate Q/R/S logic.", file=sys.stderr)
        print("It only verifies bundle structure, hash bindings, and seal integrity.", file=sys.stderr)
        print("For production verification, use the full gate verifiers.", file=sys.stderr)
        print("", file=sys.stderr)
        print("To acknowledge and proceed: belgi bundle check --in <dir> --demo", file=sys.stderr)
        return 3
    
    bundle_dir = Path(args.input).resolve()
    
    if not bundle_dir.exists():
        print(f"[belgi bundle check] ERROR: bundle directory does not exist: {bundle_dir}", file=sys.stderr)
        return 3
    if not bundle_dir.is_dir():
        print(f"[belgi bundle check] ERROR: path is not a directory: {bundle_dir}", file=sys.stderr)
        return 3
    if bundle_dir.is_symlink():
        print(f"[belgi bundle check] ERROR: symlink directory not allowed: {bundle_dir}", file=sys.stderr)
        return 3
    
    # Required bundle files (fail-closed: all must exist)
    required_files = [
        "LockedSpec.json",
        "EvidenceManifest.json",
        "SealManifest.json",
        "GateVerdict_Q.json",
        "GateVerdict_R.json",
        "GateVerdict_S.json",
    ]
    
    failures: list[str] = []
    checks_passed = 0
    checks_total = 0
    
    # Check required files exist (fail-closed: no symlinks)
    for fname in required_files:
        checks_total += 1
        fpath = bundle_dir / fname
        if not fpath.exists():
            failures.append(f"missing required file: {fname}")
        elif fpath.is_symlink():
            failures.append(f"symlink not allowed: {fname}")
        else:
            checks_passed += 1
    
    if failures:
        print(f"[belgi bundle check] FAIL: required files check", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    
    # Load files (fail-closed on parse error)
    def load_json_file(name: str) -> dict[str, Any] | None:
        try:
            p = bundle_dir / name
            return json.loads(p.read_text(encoding="utf-8", errors="strict"))
        except Exception as e:
            failures.append(f"{name}: failed to parse JSON: {e}")
            return None
    
    locked_spec = load_json_file("LockedSpec.json")
    evidence_manifest = load_json_file("EvidenceManifest.json")
    seal_manifest = load_json_file("SealManifest.json")
    verdict_q = load_json_file("GateVerdict_Q.json")
    verdict_r = load_json_file("GateVerdict_R.json")
    verdict_s = load_json_file("GateVerdict_S.json")
    
    if failures:
        print(f"[belgi bundle check] FAIL: JSON parse errors", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    
    # Verify protocol identity binding (pack_id/pack_name/manifest_sha256).
    # NOTE: source is metadata and is intentionally NOT treated as identity.
    checks_total += 1
    try:
        protocol = get_builtin_protocol_context()
        if locked_spec is not None:
            proto_pack = locked_spec.get("protocol_pack")
            if isinstance(proto_pack, dict):
                declared_pack_id = proto_pack.get("pack_id")
                declared_pack_name = proto_pack.get("pack_name")
                declared_manifest_sha256 = proto_pack.get("manifest_sha256")
                
                # Identity fields must match exactly.
                mismatches = []
                if declared_pack_id != protocol.pack_id:
                    mismatches.append(f"pack_id: declared={declared_pack_id}, builtin={protocol.pack_id}")
                if declared_pack_name != protocol.pack_name:
                    mismatches.append(f"pack_name: declared={declared_pack_name}, builtin={protocol.pack_name}")
                if declared_manifest_sha256 != protocol.manifest_sha256:
                    mismatches.append(f"manifest_sha256: declared={declared_manifest_sha256}, builtin={protocol.manifest_sha256}")
                
                if mismatches:
                    for m in mismatches:
                        failures.append(f"protocol_pack binding mismatch: {m}")
                else:
                    checks_passed += 1
            else:
                failures.append("LockedSpec.protocol_pack missing or invalid")
        else:
            failures.append("LockedSpec is None")
    except Exception as e:
        failures.append(f"protocol identity check failed: {e}")
    
    # Verify run_id consistency (FAIL-CLOSED: all 6 artifacts MUST have non-empty run_id)
    checks_total += 1
    run_ids: dict[str, str | None] = {
        "LockedSpec": locked_spec.get("run_id") if locked_spec else None,
        "EvidenceManifest": evidence_manifest.get("run_id") if evidence_manifest else None,
        "SealManifest": seal_manifest.get("run_id") if seal_manifest else None,
        "GateVerdict_Q": verdict_q.get("run_id") if verdict_q else None,
        "GateVerdict_R": verdict_r.get("run_id") if verdict_r else None,
        "GateVerdict_S": verdict_s.get("run_id") if verdict_s else None,
    }
    
    # FAIL-CLOSED: Each artifact MUST have a non-empty string run_id.
    missing_run_id = [name for name, rid in run_ids.items() if not isinstance(rid, str) or not rid]
    if missing_run_id:
        for name in missing_run_id:
            failures.append(f"{name}: run_id missing or empty (fail-closed)")
    else:
        # All present; now check uniqueness
        unique_run_ids = set(run_ids.values())
        if len(unique_run_ids) == 1:
            checks_passed += 1
        else:
            # Report which artifacts have which run_id
            failures.append(f"run_id mismatch: found {len(unique_run_ids)} distinct values")
            for name, rid in run_ids.items():
                failures.append(f"  {name}: {rid}")
    
    # Verify gate verdicts are GO (fail-closed)
    for name, verdict in [("Q", verdict_q), ("R", verdict_r), ("S", verdict_s)]:
        checks_total += 1
        if verdict is None:
            failures.append(f"GateVerdict_{name} is None")
            continue
        v = verdict.get("verdict")
        if v == "GO":
            checks_passed += 1
        elif v == "NO-GO":
            failures.append(f"GateVerdict_{name}.verdict is NO-GO")
        else:
            failures.append(f"GateVerdict_{name}.verdict invalid: expected GO|NO-GO, got {v!r}")
    
    # Verify ObjectRef hash bindings in SealManifest (FAIL-CLOSED: all must exist and hash-match)
    def verify_object_ref(ref: dict[str, Any] | None, field: str, bundle_dir: Path) -> tuple[bool, str]:
        """Verify ObjectRef exists and hash matches. Returns (ok, hash_value)."""
        if ref is None or not isinstance(ref, dict):
            failures.append(f"{field}: missing or invalid ObjectRef")
            return False, ""
        
        obj_hash = ref.get("hash")
        storage_ref = ref.get("storage_ref")
        
        if not is_hex_sha256(str(obj_hash) if obj_hash else ""):
            failures.append(f"{field}.hash: invalid SHA-256 format")
            return False, ""
        
        if not isinstance(storage_ref, str) or not storage_ref:
            failures.append(f"{field}.storage_ref: missing or empty")
            return False, ""
        
        # Resolve file path (storage_ref should be bundle-relative filename)
        # FAIL-CLOSED: file MUST exist in bundle and hash MUST match
        target_path = bundle_dir / Path(storage_ref).name
        
        if target_path.is_symlink():
            failures.append(f"{field}: symlink not allowed: {target_path.name}")
            return False, ""
        
        if not target_path.exists():
            failures.append(f"{field}: referenced file not found in bundle: {target_path.name}")
            return False, ""
        
        if not target_path.is_file():
            failures.append(f"{field}: referenced path is not a file: {target_path.name}")
            return False, ""
        
        computed = sha256_bytes(target_path.read_bytes())
        if computed != obj_hash:
            failures.append(
                f"{field}: hash mismatch for {target_path.name} "
                f"(declared={obj_hash[:16]}..., computed={computed[:16]}...)"
            )
            return False, ""
        
        return True, str(obj_hash)
    
    # Collect hashes for seal_hash verification
    locked_spec_hash = ""
    evidence_manifest_hash = ""
    gate_q_hash = ""
    gate_r_hash = ""
    
    if seal_manifest:
        for ref_field, hash_target in [
            ("locked_spec_ref", "locked_spec"),
            ("gate_q_verdict_ref", "gate_q"),
            ("gate_r_verdict_ref", "gate_r"),
            ("evidence_manifest_ref", "evidence_manifest"),
        ]:
            checks_total += 1
            ref = seal_manifest.get(ref_field)
            ok, hash_val = verify_object_ref(ref, f"SealManifest.{ref_field}", bundle_dir)
            if ok:
                checks_passed += 1
                if hash_target == "locked_spec":
                    locked_spec_hash = hash_val
                elif hash_target == "evidence_manifest":
                    evidence_manifest_hash = hash_val
                elif hash_target == "gate_q":
                    gate_q_hash = hash_val
                elif hash_target == "gate_r":
                    gate_r_hash = hash_val
    
    # Verify seal_hash (deterministic recomputation)
    checks_total += 1
    if seal_manifest and locked_spec_hash and evidence_manifest_hash and gate_q_hash and gate_r_hash:
        declared_seal_hash = seal_manifest.get("seal_hash")
        final_commit_sha = seal_manifest.get("final_commit_sha", "")
        run_id = seal_manifest.get("run_id", "")
        
        if not is_hex_sha256(str(declared_seal_hash) if declared_seal_hash else ""):
            failures.append("SealManifest.seal_hash: invalid or missing SHA-256")
        elif not final_commit_sha:
            failures.append("SealManifest.final_commit_sha: missing or empty")
        elif not run_id:
            failures.append("SealManifest.run_id: missing or empty")
        else:
            try:
                computed_seal = canonical_seal_hash(dict(seal_manifest))
            except Exception as e:
                failures.append(f"seal_hash recomputation failed: {e}")
            else:
                if computed_seal.lower() == str(declared_seal_hash).lower():
                    checks_passed += 1
                else:
                    failures.append(
                        f"seal_hash mismatch: declared={str(declared_seal_hash)[:16]}..., "
                        f"computed={computed_seal[:16]}..."
                    )
    else:
        failures.append("seal_hash check skipped: prerequisite ObjectRef checks failed")
    
    # Summary
    if failures:
        print(f"[belgi bundle check] FAIL: {checks_passed}/{checks_total} checks passed", file=sys.stderr)
        for f in failures[:15]:
            print(f"  - {f}", file=sys.stderr)
        if len(failures) > 15:
            print(f"  ... and {len(failures) - 15} more failures", file=sys.stderr)
        return 1
    
    # Success summary (run_ids all present and unique at this point)
    display_run_id = run_ids.get("SealManifest") or "UNKNOWN"
    if getattr(args, "verbose", False):
        print(f"[belgi bundle check] source: {bundle_dir}", file=sys.stdout)
        print(f"[belgi bundle check] run_id: {display_run_id}", file=sys.stdout)
        print(f"[belgi bundle check] protocol_pack: {protocol.pack_name} ({protocol.pack_id[:16]}...)", file=sys.stdout)
        print(f"[belgi bundle check] checks: {checks_passed}/{checks_total} passed", file=sys.stdout)
    print("PASS", file=sys.stdout)
    return 0


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="belgi",
        description="BELGI CLI — Protocol pack management and evidence generation tools",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    # about
    subparsers.add_parser("about", help="Print package identity info")

    # init
    p_init = subparsers.add_parser("init", help="Initialize BELGI adopter defaults in a repository")
    p_init.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_init.add_argument(
        "--workspace",
        default=DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {DEFAULT_WORKSPACE_REL})",
    )
    p_init.add_argument(
        "--refresh-pin",
        action="store_true",
        help="Explicitly refresh protocol pack pins in adopter.toml (and overlay manifest if present)",
    )

    # policy (subparser group)
    p_policy = subparsers.add_parser("policy", help="Policy helper commands")
    policy_subs = p_policy.add_subparsers(dest="policy_command", help="Policy subcommand")

    # policy stub
    p_policy_stub = policy_subs.add_parser("stub", help="Generate deterministic PolicyReportPayload stub JSON")
    p_policy_stub.add_argument("--out", required=True, help="Output JSON path")
    p_policy_stub.add_argument("--run-id", required=True, help="Run ID for PolicyReportPayload")
    p_policy_stub.add_argument(
        "--check-id",
        action="append",
        default=[],
        help="Check ID to mark as passed (repeatable; at least one required)",
    )
    p_policy_stub.add_argument(
        "--generated-at",
        default="1970-01-01T00:00:00Z",
        help="RFC3339 generated_at value (default: 1970-01-01T00:00:00Z)",
    )
    p_policy_stub.set_defaults(func=cmd_policy_stub)

    # policy check-overlay
    p_policy_check_overlay = policy_subs.add_parser(
        "check-overlay",
        help="Evaluate adopter overlay requirements against an EvidenceManifest (overlay-only preflight)",
    )
    p_policy_check_overlay.add_argument("--repo", default=".", help="Repo root")
    p_policy_check_overlay.add_argument(
        "--evidence-manifest",
        required=True,
        help="Repo-relative path to EvidenceManifest.json",
    )
    p_policy_check_overlay.add_argument(
        "--overlay",
        required=True,
        help="Repo-relative path to overlay dir or DomainPackManifest.json",
    )
    p_policy_check_overlay.set_defaults(func=cmd_policy_check_overlay)

    # run (subparser group)
    p_run = subparsers.add_parser("run", help="Run workspace helper commands")
    p_run.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_run.add_argument("--tier", choices=sorted(ALLOWED_RUN_TIERS), help="Tier ID for deterministic run scaffolding")
    p_run.add_argument(
        "--workspace",
        default=DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {DEFAULT_WORKSPACE_REL})",
    )
    p_run.add_argument(
        "--intent-spec",
        default=None,
        help='Repo-relative intent/spec source to bind into run_key (default: auto-generated "(auto)")',
    )
    run_subs = p_run.add_subparsers(dest="run_command", help="Run subcommand")

    # run new
    p_run_new = run_subs.add_parser("new", help="Create deterministic run workspace from adopter template")
    p_run_new.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_run_new.add_argument(
        "--workspace",
        default=DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {DEFAULT_WORKSPACE_REL})",
    )
    p_run_new.add_argument("--run-id", required=True, help="Deterministic run ID")
    p_run_new.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing run workspace files deterministically",
    )

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify deterministic run summaries and manifests")
    p_verify.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_verify.add_argument(
        "--in",
        dest="input",
        default=None,
        help="Repo-relative run summary, attempt directory, run_key directory, or runs root",
    )
    p_verify.add_argument(
        "--workspace",
        default=DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {DEFAULT_WORKSPACE_REL})",
    )

    # manifest (subparser group)
    p_manifest = subparsers.add_parser("manifest", help="EvidenceManifest mutation helpers")
    manifest_subs = p_manifest.add_subparsers(dest="manifest_command", help="Manifest subcommand")

    # manifest add
    p_manifest_add = manifest_subs.add_parser("add", help="Add or update an artifact entry in EvidenceManifest")
    p_manifest_add.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_manifest_add.add_argument("--manifest", required=True, help="Repo-relative path to EvidenceManifest.json")
    p_manifest_add.add_argument("--artifact", required=True, help="Repo-relative path to artifact file")
    p_manifest_add.add_argument("--kind", required=True, help="Artifact kind (must exist in schema enum)")
    p_manifest_add.add_argument("--id", dest="artifact_id", required=True, help="Artifact id")
    p_manifest_add.add_argument("--media-type", required=True, help="Artifact media_type")
    p_manifest_add.add_argument("--produced-by", required=True, help="Artifact produced_by")
    
    # pack (subparser group)
    p_pack = subparsers.add_parser("pack", help="Protocol pack management commands")
    pack_subs = p_pack.add_subparsers(dest="pack_command", help="Pack subcommand")
    
    # pack build
    p_pack_build = pack_subs.add_parser("build", help="Build/update protocol pack manifest")
    p_pack_build.add_argument("--in", dest="input", help="Input pack directory")
    p_pack_build.add_argument("--out", dest="output", help="Output directory (default: same as --in)")
    p_pack_build.add_argument("--pack-name", default="belgi-protocol-pack-v1", help="Pack name for manifest")
    
    # pack verify
    p_pack_verify = pack_subs.add_parser("verify", help="Verify protocol pack manifest")
    p_pack_verify.add_argument("--in", dest="input", help="Pack directory to verify")
    p_pack_verify.add_argument("--builtin", action="store_true", help="Verify builtin pack from installed package")
    p_pack_verify.add_argument("--verbose", action="store_true", help="Verbose output")
    
    # bundle (subparser group)
    p_bundle = subparsers.add_parser("bundle", help="Evidence bundle commands")
    bundle_subs = p_bundle.add_subparsers(dest="bundle_command", help="Bundle subcommand")
    
    # bundle check
    p_bundle_check = bundle_subs.add_parser("check", help="Check an evidence bundle (demo-grade checker)")
    p_bundle_check.add_argument("--in", dest="input", required=True, help="Bundle directory to check")
    p_bundle_check.add_argument(
        "--demo", action="store_true",
        help="Acknowledge this is a demo-grade checker (required)"
    )
    p_bundle_check.add_argument("--verbose", action="store_true", help="Verbose output")
    
    # supplychain-scan
    p_sc = subparsers.add_parser("supplychain-scan", help="Run supplychain scan and produce policy.supplychain artifact")
    p_sc.add_argument("--repo", default=".", help="Repo root")
    p_sc.add_argument("--run-id", default="unknown", help="Run ID to embed in the PolicyReportPayload (default: unknown)")
    p_sc.add_argument(
        "--evaluated-revision",
        default="HEAD~1",
        help="Git revision to diff against (e.g. HEAD~1 or commit sha). Default: HEAD~1",
    )
    p_sc.add_argument(
        "--out",
        default="out/policy-supplychain.json",
        help="Output JSON path (default: out/policy-supplychain.json)",
    )
    p_sc.add_argument("--deterministic", action="store_true", help="Use fixed timestamps for deterministic output")
    p_sc.set_defaults(func=cmd_supplychain_scan)

    # adversarial-scan
    p_adv = subparsers.add_parser("adversarial-scan", help="Run adversarial scan and produce policy.adversarial_scan artifact")
    p_adv.add_argument("--repo", default=".", help="Repo root")
    p_adv.add_argument("--run-id", default="unknown", help="Run ID to embed in the PolicyReportPayload (default: unknown)")
    p_adv.add_argument(
        "--out",
        default="out/policy-adversarial-scan.json",
        help="Output JSON path (default: out/policy-adversarial-scan.json)",
    )
    p_adv.add_argument("--deterministic", action="store_true", help="Use fixed timestamps for deterministic output")
    p_adv.set_defaults(func=cmd_adversarial_scan)

    args = parser.parse_args(argv)
    
    if args.command == "about":
        return cmd_about(args)
    elif args.command == "pack":
        if args.pack_command == "build":
            if not args.input:
                print("[belgi pack build] ERROR: --in required", file=sys.stderr)
                return 3
            return cmd_pack_build(args)
        elif args.pack_command == "verify":
            return cmd_pack_verify(args)
        else:
            p_pack.print_help()
            return 3
    elif args.command == "init":
        return cmd_init(args)
    elif args.command == "policy":
        if args.policy_command in ("stub", "check-overlay"):
            return int(args.func(args))
        p_policy.print_help()
        return 3
    elif args.command == "run":
        if args.run_command == "new":
            return cmd_run_new(args)
        if getattr(args, "tier", None):
            return cmd_run(args)
        p_run.print_help()
        return 3
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "manifest":
        if args.manifest_command == "add":
            return cmd_manifest_add(args)
        p_manifest.print_help()
        return 3
    elif args.command == "bundle":
        if args.bundle_command == "check":
            return cmd_bundle_check(args)
        else:
            p_bundle.print_help()
            return 3
    elif args.command == "supplychain-scan":
        return int(args.func(args))
    elif args.command == "adversarial-scan":
        return int(args.func(args))
    else:
        parser.print_help()
        return 3


if __name__ == "__main__":
    sys.exit(main())
