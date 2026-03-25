from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, metadata, version
from importlib.resources import as_file, files
from pathlib import Path, PurePosixPath

from belgi.cli_app import render as cli_render
from belgi.core.run_orchestrator import (
    CHAIN_OUT_DIRNAME,
    CHAIN_REPO_DIRNAME,
    OperatorAnchorInputs,
    RunEvidenceInputs,
    orchestrate_chain_run,
    render_default_intent_spec,
)

ABOUT_PHILOSOPHY = '"Hayatta en hakiki mürşit ilimdir." (M.K. Atatürk)'
ABOUT_DEDICATION = "Bilge (8)"
ABOUT_REPO_URL = "https://github.com/belgi-protocol/belgi"
DEFAULT_WORKSPACE_REL = ".belgi"
RUN_SUMMARY_FILENAME = "run.summary.json"
ATTEMPT_ID_PATTERN = re.compile(r"^attempt-(\d+)$")
RUN_KEY_DIR_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_RUN_TIERS = {"tier-0", "tier-1", "tier-2", "tier-3"}
RUN_INPUTS_DIRNAME = "inputs"
RUN_ANCHORS_DIRNAME = "anchors"
RUN_ANCHORS_APPROVALS_DIRNAME = "approvals"
RUN_ANCHORS_KEYS_DIRNAME = "keys"
RUN_ANCHORS_SIGNING_DIRNAME = "signing"
RUN_EVIDENCE_DIRNAME = "evidence"
RUN_ENVIRONMENT_DIRNAME = "environment"
RUN_ENV_TOOLCHAIN_SET_FILENAME = "toolchain-set.json"
RUN_ENV_TOLERANCES_FILENAME = "tolerances.json"
RUN_STORE_DIRNAME = "store"
RUN_STORE_RUNS_REPO_REL = "store/runs"
RUN_INTENT_REPO_REL = "inputs/intent/IntentSpec.core.md"
RUN_WAIVERS_DIR_REPO_REL = "inputs/waivers"
RUN_WAIVERS_APPLIED_REPO_REL = "inputs/waivers_applied.json"
RUN_POINTER_RUN_KEY_REPO_REL = "run_key.txt"
RUN_POINTER_LAST_ATTEMPT_REPO_REL = "last_attempt.txt"
RUN_POINTER_OPEN_VERDICT_REPO_REL = "open_verdict.txt"
RUN_POINTER_OPEN_EVIDENCE_REPO_REL = "open_evidence.txt"
RC_GO = 0
RC_NO_GO = 10
RC_USER_ERROR = 20
RC_INTERNAL_ERROR = 30
_RUN_NO_GO_GENERIC_NEXT = "Do inspect the reported reason, fix inputs, then rerun `belgi run`."
_SHA1_40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$")
_CI_BASE_SHA_ENV_ORDER: tuple[str, ...] = (
    "BELGI_BASE_SHA",
    "GITHUB_BASE_SHA",
)
_ANSI_RESET = "\x1b[0m"
_ANSI_STATUS_COLORS: dict[str, str] = {
    "GO": "\x1b[32m",
    "NO-GO": "\x1b[31m",
    "USER_ERROR": "\x1b[33m",
    "INTERNAL_ERROR": "\x1b[35m",
}
_STAGE_FORWARDER_NOTE = (
    "Strict forwarder to repo-local canonical chain entrypoints (`python -m chain.*`). "
    "May be unavailable in wheel-only installs where `chain/*` is not present."
)

class _UserInputError(ValueError):
    """User-facing input/configuration issue (mapped to RC_USER_ERROR)."""

def cmd_about(_: argparse.Namespace) -> int:
    """Print concise package/protocol identity info."""
    from belgi.protocol.pack import MANIFEST_FILENAME, get_builtin_protocol_context

    try:
        pkg_version = version("belgi")
    except PackageNotFoundError:
        pkg_version = "0.0.0"

    pkg_name = "belgi"
    try:
        meta = metadata("belgi")
        pkg_name = str(meta.get("Name") or pkg_name)
    except PackageNotFoundError:
        pass

    protocol = get_builtin_protocol_context()
    print(f"{pkg_name} {pkg_version}")
    print(f"protocol_pack: {protocol.pack_name}")
    print(f"pack_id: {protocol.pack_id}")
    print(f"manifest_sha256: {protocol.manifest_sha256}")
    print("resources: belgi/_protocol_packs/v1")

    open_path: Path | None = None
    manifest_node = files("belgi._protocol_packs.v1").joinpath(MANIFEST_FILENAME)
    try:
        with as_file(manifest_node) as p:
            open_path = Path(p).resolve()
    except Exception:
        open_path = None
    if open_path is not None:
        platform_name, cmd = _open_command_for_platform(path=open_path)
        print(f"open_{platform_name}: {cmd}")
    return 0

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
            shell=False,
        )
    except Exception as e:
        raise ValueError(
            "cannot determine repo HEAD SHA; ensure --repo is a git repository with at least one commit"
        ) from e
    sha = cp.stdout.strip()
    if len(sha) == 40 and all(c in "0123456789abcdefABCDEF" for c in sha):
        return sha.lower()
    raise ValueError("cannot determine repo HEAD SHA; `git rev-parse HEAD` returned an invalid value")

def _resolve_commit_sha(repo_root: Path, revision: str, *, label: str) -> str:
    raw = str(revision or "").strip()
    if not raw:
        raise ValueError(f"{label} missing/empty")
    if not _SHA1_40_RE.fullmatch(raw):
        raise ValueError(f"{label} must be a stable 40-hex commit SHA")
    try:
        cp = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--verify", f"{raw}^{{commit}}"],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
        )
    except Exception as e:
        raise ValueError(f"{label} is not resolvable in repository history") from e
    resolved = cp.stdout.strip()
    if not _SHA1_40_RE.fullmatch(resolved):
        raise ValueError(f"{label} resolved to a non-40-hex commit SHA")
    return resolved.lower()

def _current_upstream_ref(repo_root: Path) -> str | None:
    cp = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    if cp.returncode != 0:
        return None
    ref = cp.stdout.strip()
    if not ref:
        return None
    return ref

def _merge_base_with_upstream(repo_root: Path) -> str:
    cp = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--", "HEAD", "@{u}"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    if cp.returncode != 0:
        msg = (cp.stderr or cp.stdout or "").strip()
        raise ValueError(f"cannot resolve merge-base(HEAD, @{{u}}): {msg or 'unknown error'}")
    merge_base = cp.stdout.strip()
    if not _SHA1_40_RE.fullmatch(merge_base):
        raise ValueError("merge-base(HEAD, @{u}) did not resolve to a 40-hex commit SHA")
    return _resolve_commit_sha(repo_root, merge_base, label="merge-base revision")

def _discover_base_revision(
    *,
    repo_root: Path,
    explicit_base_revision: str | None,
) -> tuple[str, str, str | None]:
    for env_name in _CI_BASE_SHA_ENV_ORDER:
        env_val = os.environ.get(env_name)
        if env_val is None or not str(env_val).strip():
            continue
        try:
            sha = _resolve_commit_sha(repo_root, str(env_val), label=f"{env_name}")
        except ValueError as e:
            raise _UserInputError(f"invalid CI base revision from {env_name}: {e}") from e
        return sha, "ci_env", None

    upstream_ref = _current_upstream_ref(repo_root)
    if upstream_ref is not None:
        try:
            sha = _merge_base_with_upstream(repo_root)
        except ValueError as e:
            raise _UserInputError(f"cannot resolve base revision from upstream {upstream_ref}: {e}") from e
        return sha, "merge_base", upstream_ref

    explicit_raw = str(explicit_base_revision or "").strip()
    if explicit_raw:
        try:
            sha = _resolve_commit_sha(repo_root, explicit_raw, label="--base-revision")
        except ValueError as e:
            raise _UserInputError(str(e)) from e
        return sha, "explicit", None

    raise _UserInputError(
        "base revision unavailable: no CI base SHA env and no upstream tracking branch. "
        "Do set upstream tracking (`git branch --set-upstream-to origin/<branch>`) or rerun with "
        "`--base-revision <40-hex SHA>`."
    )

def _validate_tier_id(raw: str) -> str:
    tier_id = str(raw or "").strip()
    if tier_id not in ALLOWED_RUN_TIERS:
        raise ValueError("--tier must be one of: tier-0, tier-1, tier-2, tier-3")
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
    base_revision: str,
    evaluated_revision: str,
    protocol_pack_name: str,
    protocol_pack_id: str,
    protocol_manifest_sha256: str,
    declared_toolchain_set_ref: str | None = None,
    declared_toolchain_refs: list[str] | None = None,
    declared_tolerances_ref: str | None = None,
) -> dict[str, object]:
    normalized_inputs: dict[str, object] = {
        "intent_spec_source": intent_source_rel,
        "tier_id": tier_id,
        "workspace_root": workspace_rel,
    }
    if declared_toolchain_set_ref is not None:
        normalized_inputs["toolchain_set_ref"] = declared_toolchain_set_ref
    if declared_toolchain_refs:
        normalized_inputs["toolchain_refs"] = sorted(str(ref) for ref in declared_toolchain_refs)
    if declared_tolerances_ref is not None:
        normalized_inputs["tolerances_ref"] = declared_tolerances_ref
    return {
        "schema_version": "1.0.0",
        "summary_kind": "belgi.run_key.preimage",
        "normalized_inputs": normalized_inputs,
        "intent_spec_sha256": intent_spec_sha256,
        "belgi": {
            "package_version": _package_version(),
            "repo_head_sha": evaluated_revision,
            "base_revision_sha": base_revision,
            "evaluated_revision_sha": evaluated_revision,
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

def _write_text_if_changed(path: Path, text: str) -> str | None:
    if path.exists():
        if path.is_symlink():
            raise ValueError(f"symlink not allowed: {path}")
        if not path.is_file():
            raise ValueError(f"expected file path but found non-file: {path}")
        existing = path.read_text(encoding="utf-8", errors="strict")
        if existing == text:
            return None
        _write_text(path, text)
        return "updated"
    _write_text(path, text)
    return "created"

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
    store_root = f"{workspace_rel}/store/runs"
    intent_path = f"{workspace_rel}/runs/run-001/inputs/intent/IntentSpec.core.md"
    toolchain_set_path = (
        f"{workspace_rel}/runs/run-001/inputs/environment/{RUN_ENV_TOOLCHAIN_SET_FILENAME}"
    )
    tolerances_path = (
        f"{workspace_rel}/runs/run-001/inputs/environment/{RUN_ENV_TOLERANCES_FILENAME}"
    )
    return (
        "# BELGI Quickstart\n\n"
        "Generated by `belgi init`; this file is managed and may be overwritten deterministically.\n\n"
        "## Quickstart\n"
        "```bash\n"
        "belgi init --repo .\n"
        "belgi run new --repo . --run-id run-001\n"
        f"# edit: {intent_path}\n"
        "belgi run --repo . --tier tier-1 --intent-spec "
        f"{intent_path} --base-revision <SHA40>\n"
        f"# optional: --toolchain-set-ref env.toolchains={toolchain_set_path}\n"
        f"# optional: --toolchain-ref deps.requirements=requirements.txt\n"
        f"# optional: --tolerances-ref tier.tolerances={tolerances_path}\n"
        "belgi verify --repo .\n"
        "```\n\n"
        "Optional shared run object inputs:\n"
        "- Use `--toolchain-set-ref <object_id>=<repo-relative-path>` to bind an authoritative ToolchainSet object on the shared `belgi run` spine.\n"
        f"- Explicit ToolchainSet refs are pre-lock operator inputs. Accepted only as the current run canonical input: `{toolchain_set_path}`.\n"
        "- BELGI stages that ToolchainSet into locked/store authority before C1; later stages consume the locked/store copy, not ambient workspace bytes.\n"
        "- ToolchainSet member declaration paths must still point at actual repo-relative dependency/toolchain declaration surfaces in the evaluated revision truth envelope.\n"
        "- Repeat `--toolchain-ref <object_id>=<repo-relative-path>` only as shorthand when you want `belgi run` to generate that ToolchainSet authority for you.\n"
        "- Do not mix `--toolchain-set-ref` with shorthand `--toolchain-ref` values.\n"
        "- `toolchain.main` is reserved for the built-in generated run toolchain input and is never operator-declared inside ToolchainSet.\n\n"
        "- Use `--tolerances-ref <object_id>=<repo-relative-path>` to bind a real locked Tolerances object into `LockedSpec.tier.tolerances_ref`.\n"
        f"- Explicit Tolerances refs are pre-lock operator inputs. Accepted only as the current run canonical input: `{tolerances_path}`.\n"
        "- BELGI stages that Tolerances object into locked/store authority before C1; later stages consume the locked/store copy, not ambient workspace bytes.\n"
        "- Recommended object id: `tier.tolerances`.\n"
        "- If `--tolerances-ref` is omitted, `belgi run` materializes the canonical Tolerances object from the selected tier pack and locks that generated object automatically.\n"
        "- Numeric scope budgets no longer live in `IntentSpec`; move any legacy `IntentSpec.scope.max_*` values into the Tolerances object.\n\n"
        "## Layout map\n"
        f"- `{run_root}/<run_id>/` = human workspace + pointers.\n"
        f"- `{store_root}/<run_key>/<attempt_id>/` = authoritative artifacts.\n"
        "- `open_verdict.txt` and `open_evidence.txt` point to the latest verdict/evidence paths.\n\n"
        "## On NO-GO\n"
        "- For public `NO-GO (10)` output, check `next` first.\n"
        "- It prefers `GateVerdict.<Q|R|S>.json remediation.next_instruction` from a produced `NO-GO` gate verdict.\n"
        "- Otherwise it uses current `C1IntentParseError.json next_instruction` when present.\n"
        "- Otherwise it falls back to generic CLI guidance.\n"
        "- Separate public `USER_ERROR (20)` failures use direct CLI guidance for input, argument, or repo-state problems.\n"
        "- Then inspect `open_verdict.txt` / `gate_verdict_path` and `open_evidence.txt` / `evidence_manifest_path` for the `NO-GO (10)` path.\n\n"
        "## What this is\n"
        "- Deterministic verification workflow for LLM-assisted code changes.\n"
        "- Machine-readable evidence and replay-oriented artifact structure.\n"
        "- Fail-closed contract checks across Q/R/S gates.\n\n"
        "## What this is not\n"
        "- Not an auto-fixer.\n"
        "- Not a decision-maker.\n"
        "- Not a waiver applier.\n"
    )

def _render_templates_readme(*, workspace_rel: str) -> str:
    return (
        "# BELGI Template Seeds\n\n"
        f"- `{workspace_rel}/templates/IntentSpec.core.template.md` is a local seed/reset template.\n"
        "- `belgi run new` copies template bytes into run inputs.\n"
        "- Editing template files does not alter immutable run artifacts already in `.belgi/store/runs/`.\n"
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

    protocol = None
    try:
        protocol = get_builtin_protocol_context()
    except Exception as e:
        print(f"[belgi init] ERROR: cannot load builtin protocol pack identity: {e}", file=sys.stderr)
        return 3
    if protocol is None:
        print("[belgi init] ERROR: cannot load builtin protocol pack identity", file=sys.stderr)
        return 3

    adopter_dir = workspace_dir
    runs_dir = adopter_dir / "runs"
    store_runs_dir = adopter_dir / "store" / "runs"
    overlay_dir = repo_root / "belgi_pack"
    templates_dir = adopter_dir / "templates"
    adopter_toml_path = adopter_dir / "adopter.toml"
    adopter_readme_path = adopter_dir / "README.md"
    templates_readme_path = templates_dir / "README.md"
    overlay_manifest_path = overlay_dir / "DomainPackManifest.json"
    intent_template_path = templates_dir / "IntentSpec.core.template.md"

    # Guard against symlink directories and conflicting file paths.
    for d in (adopter_dir, runs_dir, store_runs_dir, overlay_dir, templates_dir):
        if d.exists() and not d.is_dir():
            print(f"[belgi init] ERROR: expected directory path but found non-directory: {d}", file=sys.stderr)
            return 3
        if d.exists() and d.is_symlink():
            print(f"[belgi init] ERROR: symlink directory not allowed: {d}", file=sys.stderr)
            return 3

    adopter_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)
    store_runs_dir.mkdir(parents=True, exist_ok=True)
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
        if _write_text_if_missing(templates_readme_path, _render_templates_readme(workspace_rel=workspace_rel)):
            created.append(templates_readme_path)

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

        readme_state = _write_text_if_changed(adopter_readme_path, _render_adopter_readme(workspace_rel=workspace_rel))
        if readme_state == "created":
            created.append(adopter_readme_path)
        elif readme_state == "updated":
            updated.append(adopter_readme_path)

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

    _ = (created, updated)
    readme_rel = f"{workspace_rel}/README.md"
    print(
        f"[belgi init] next: {readme_rel} ; belgi run new --repo . --run-id run-001",
        file=sys.stderr,
    )
    return 0

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
    if RUN_KEY_DIR_PATTERN.fullmatch(rid.lower()):
        raise ValueError("--run-id must not be a 64-hex run_key value")
    return rid

def _validate_waiver_id(raw: str) -> str:
    wid = str(raw or "").strip()
    if not wid:
        raise ValueError("--waiver-id missing/invalid")
    if "/" in wid or "\\" in wid:
        raise ValueError("--waiver-id must not contain path separators")
    if wid in (".", ".."):
        raise ValueError("--waiver-id missing/invalid")
    if ":" in wid or "\x00" in wid:
        raise ValueError("--waiver-id contains forbidden characters")
    return wid

def _run_intent_path(run_dir: Path) -> Path:
    return run_dir.joinpath(*RUN_INTENT_REPO_REL.split("/"))

def _run_waivers_dir(run_dir: Path) -> Path:
    return run_dir.joinpath(*RUN_WAIVERS_DIR_REPO_REL.split("/"))

def _run_waivers_applied_path(run_dir: Path) -> Path:
    return run_dir.joinpath(*RUN_WAIVERS_APPLIED_REPO_REL.split("/"))

def _run_pointer_run_key_path(run_dir: Path) -> Path:
    return run_dir.joinpath(*RUN_POINTER_RUN_KEY_REPO_REL.split("/"))

def _run_pointer_last_attempt_path(run_dir: Path) -> Path:
    return run_dir.joinpath(*RUN_POINTER_LAST_ATTEMPT_REPO_REL.split("/"))

def _run_pointer_open_verdict_path(run_dir: Path) -> Path:
    return run_dir.joinpath(*RUN_POINTER_OPEN_VERDICT_REPO_REL.split("/"))

def _run_pointer_open_evidence_path(run_dir: Path) -> Path:
    return run_dir.joinpath(*RUN_POINTER_OPEN_EVIDENCE_REPO_REL.split("/"))

def _resolve_store_runs_dir(*, workspace_dir: Path, must_exist: bool) -> Path:
    store_dir = workspace_dir / RUN_STORE_DIRNAME
    if store_dir.exists() and (store_dir.is_symlink() or not store_dir.is_dir()):
        raise ValueError(f"invalid store directory: {store_dir}")
    runs_dir = store_dir / "runs"
    if runs_dir.exists() and (runs_dir.is_symlink() or not runs_dir.is_dir()):
        raise ValueError(f"invalid store runs directory: {runs_dir}")
    if must_exist and not runs_dir.exists():
        raise ValueError(f"store runs directory missing: {runs_dir}")
    return runs_dir

def _is_legacy_run_key_dir(path: Path) -> bool:
    if path.is_symlink() or not path.is_dir():
        return False
    if not RUN_KEY_DIR_PATTERN.fullmatch(path.name.lower()):
        return False
    attempts: list[Path] = []
    for child in sorted(path.iterdir(), key=lambda p: p.name):
        if child.name.startswith(".") and not child.is_symlink():
            continue
        if child.is_symlink() or not child.is_dir():
            return False
        if ATTEMPT_ID_PATTERN.fullmatch(child.name) is None:
            return False
        summary = child / RUN_SUMMARY_FILENAME
        if not summary.exists() or summary.is_symlink() or not summary.is_file():
            return False
        attempts.append(child)
    return len(attempts) > 0

def _migrate_legacy_run_key_dirs(
    *,
    workspace_runs_dir: Path,
    store_runs_dir: Path,
    repo_root: Path,
) -> list[str]:
    from belgi.core.jail import safe_relpath

    if workspace_runs_dir.exists() and (workspace_runs_dir.is_symlink() or not workspace_runs_dir.is_dir()):
        raise ValueError(f"invalid runs directory: {workspace_runs_dir}")
    workspace_runs_dir.mkdir(parents=True, exist_ok=True)

    if store_runs_dir.exists() and (store_runs_dir.is_symlink() or not store_runs_dir.is_dir()):
        raise ValueError(f"invalid store runs directory: {store_runs_dir}")
    store_runs_dir.mkdir(parents=True, exist_ok=True)

    migrated: list[str] = []
    for child in sorted(workspace_runs_dir.iterdir(), key=lambda p: p.name):
        if child.name.startswith(".") and not child.is_symlink():
            continue
        if not _is_legacy_run_key_dir(child):
            continue
        target = store_runs_dir / child.name
        if target.exists():
            raise _UserInputError(
                "legacy/store run directory collision for run_key "
                f"{child.name}: both `{safe_relpath(repo_root, child)}` and "
                f"`{safe_relpath(repo_root, target)}` exist. "
                "Do keep only one authoritative copy under `.belgi/store/runs/` and retry."
            )
        try:
            child.rename(target)
        except OSError as e:
            raise _UserInputError(
                "legacy run directory migration failed for "
                f"`{safe_relpath(repo_root, child)}` -> `{safe_relpath(repo_root, target)}`: {e}. "
                "Do move it manually, then rerun."
            ) from e
        migrated.append(child.name)
    return migrated

def _resolve_run_dir(*, repo_root: Path, workspace_rel: str, run_id: str, must_exist: bool) -> Path:
    from belgi.core.jail import resolve_repo_rel_path

    run_rel = f"{workspace_rel}/runs/{run_id}"
    run_dir = resolve_repo_rel_path(
        repo_root,
        run_rel,
        must_exist=must_exist,
        must_be_file=False,
        allow_backslashes=False,
        forbid_symlinks=True,
    )
    if run_dir.is_symlink() or (must_exist and not run_dir.is_dir()):
        raise ValueError(f"invalid run workspace path: {run_dir}")
    return run_dir

def _render_run_waivers_applied_doc(*, run_id: str, waivers: list[str]) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "waivers": sorted(dict.fromkeys(waivers)),
    }

def _load_run_waivers_applied_refs(*, repo_root: Path, run_dir: Path, run_id: str) -> list[str]:
    from belgi.core.jail import resolve_storage_ref

    applied_path = _run_waivers_applied_path(run_dir)
    if not applied_path.exists():
        return []
    if applied_path.is_symlink() or not applied_path.is_file():
        raise ValueError(f"invalid run waiver refs file: {applied_path}")
    try:
        doc = json.loads(applied_path.read_text(encoding="utf-8", errors="strict"))
    except Exception as e:
        raise ValueError(f"run waiver refs are not valid UTF-8 JSON: {e}") from e
    if not isinstance(doc, dict):
        raise ValueError("run waiver refs must be a JSON object")
    if str(doc.get("run_id") or "") != run_id:
        raise ValueError("run waiver refs run_id mismatch")
    waivers_raw = doc.get("waivers")
    if waivers_raw is None:
        return []
    if not isinstance(waivers_raw, list):
        raise ValueError("run waiver refs `waivers` must be an array")

    refs: list[str] = []
    seen: set[str] = set()
    for entry in waivers_raw:
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError("run waiver refs must contain non-empty strings")
        ref = entry.strip()
        if ref in seen:
            raise ValueError(f"duplicate run waiver ref: {ref}")
        seen.add(ref)
        resolved = resolve_storage_ref(repo_root, ref)
        if not resolved.exists() or resolved.is_symlink() or not resolved.is_file():
            raise ValueError(f"run waiver ref missing/invalid: {ref}")
        if resolved.suffix.lower() != ".json":
            raise ValueError(f"run waiver ref must point to a .json file: {ref}")
        refs.append(ref)
    refs.sort()
    return refs

def _infer_run_id_from_intent_source(*, workspace_rel: str, intent_source_rel: str) -> str | None:
    ws_norm = str(workspace_rel).strip().strip("/")
    source_norm = str(intent_source_rel).strip().strip("/")
    expected_suffix = "/".join(RUN_INTENT_REPO_REL.split("/"))
    prefix = f"{ws_norm}/runs/"
    if not source_norm.startswith(prefix):
        return None
    if not source_norm.endswith(expected_suffix):
        return None
    middle = source_norm[len(prefix) : -len(expected_suffix)]
    middle = middle.strip("/")
    if not middle or "/" in middle:
        return None
    return middle

def _render_runbook_template(*, run_id: str) -> str:
    anchors_root = f".belgi/runs/{run_id}/inputs/anchors"
    evidence_root = f".belgi/runs/{run_id}/inputs/evidence"
    environment_root = f".belgi/runs/{run_id}/inputs/environment"
    return (
        "# RUN\n\n"
        f"Run ID: `{run_id}`\n\n"
        "Contract-first operator loop:\n\n"
        "1. Edit `inputs/intent/IntentSpec.core.md`.\n"
        "2. (Optional) Create and apply waiver drafts:\n\n"
        "```bash\n"
        f"belgi waiver new --repo . --run-id {run_id} --gate R --rule-id RULE-ID --waiver-id waiver-001 --expires-at 2100-01-01T00:00:00Z\n"
        f"belgi waiver apply --repo . --run-id {run_id} --waiver .belgi/runs/{run_id}/inputs/waivers/waiver-001.json\n"
        "```\n\n"
        "3. Resolve a stable SHA40:\n\n"
        "```bash\n"
        "BASE_SHA40=\"$(git rev-parse HEAD)\"\n"
        "```\n\n"
        "4. Prepare Operator Anchors when tier policy requires them:\n\n"
        f"- approvals: `{anchors_root}/approvals/hotl_approval.json`\n"
        f"- keys: `{anchors_root}/keys/attestation_pubkey.hex`, `{anchors_root}/keys/seal_pubkey.hex`\n"
        f"- signing: `{anchors_root}/signing/attestation_signing_key.hex` plus either `{anchors_root}/signing/seal_private_key.hex` or `{anchors_root}/signing/seal_signature.b64`\n\n"
        "Optional shared environment objects:\n\n"
        f"- ToolchainSet: `{environment_root}/toolchain-set.json`\n"
        f"- Tolerances: `{environment_root}/tolerances.json`\n\n"
        "If you want explicit shared environment objects on this run, author the canonical current-run files first:\n\n"
        "```bash\n"
        f"mkdir -p {environment_root}\n"
        f"cat > {environment_root}/{RUN_ENV_TOOLCHAIN_SET_FILENAME} <<'JSON'\n"
        "{\n"
        '  "schema_version": "1.0.0",\n'
        '  "toolchain_set_id": "env.toolchains",\n'
        '  "refs": [\n'
        "    {\n"
        '      "id": "deps.requirements",\n'
        '      "path": "requirements-dev.txt"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "JSON\n"
        f"cat > {environment_root}/{RUN_ENV_TOLERANCES_FILENAME} <<'JSON'\n"
        "{\n"
        '  "schema_version": "1.0.0",\n'
        '  "tier_id": "tier-1",\n'
        '  "scope_budgets": {\n'
        '    "max_touched_files": 50,\n'
        '    "max_loc_delta": 5000\n'
        "  }\n"
        "}\n"
        "JSON\n"
        "```\n\n"
        "Then bind them on the same shipped run spine:\n\n"
        "```bash\n"
        f"belgi run --repo . --tier tier-1 --intent-spec .belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md --base-revision \"${{BASE_SHA40}}\" \\\n"
        f"  --toolchain-set-ref env.toolchains=.belgi/runs/{run_id}/inputs/environment/{RUN_ENV_TOOLCHAIN_SET_FILENAME} \\\n"
        f"  --tolerances-ref tier.tolerances=.belgi/runs/{run_id}/inputs/environment/{RUN_ENV_TOLERANCES_FILENAME}\n"
        "```\n\n"
        "If you run a different tier, keep the same canonical paths and change only the Tolerances `tier_id` / ceilings to match that selected tier.\n\n"
        "5. Prepare Tier-3 evidence only when Tier-3 is selected:\n\n"
        f"- evidence: `{evidence_root}/genesis_seal.json`\n"
        "- canonical Tier-3 authority remains `belgi/anchor/v1/TrustAnchor.json`; it is not an Operator Anchor.\n\n"
        "6. Run BELGI:\n\n"
        "```bash\n"
        f"belgi run --repo . --tier tier-1 --intent-spec .belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md --base-revision \"${{BASE_SHA40}}\"\n"
        "```\n\n"
        "Optional shared run object inputs:\n\n"
        "- use `--toolchain-set-ref <object_id>=<repo-relative-path>` to bind an authoritative ToolchainSet object on the same `belgi run` spine.\n"
        f"- explicit ToolchainSet refs are pre-lock operator inputs. Accepted only as the current run canonical input: `{environment_root}/{RUN_ENV_TOOLCHAIN_SET_FILENAME}`.\n"
        "- BELGI stages that ToolchainSet into locked/store authority before C1; later stages consume the locked/store copy, not ambient workspace bytes.\n"
        "- ToolchainSet member declaration paths must still point at actual repo-relative dependency/toolchain declaration surfaces in the evaluated revision truth envelope.\n"
        "- repeat `--toolchain-ref <object_id>=<repo-relative-path>` only as shorthand when you want `belgi run` to generate ToolchainSet authority for you.\n"
        "- do not mix `--toolchain-set-ref` with shorthand `--toolchain-ref` values.\n"
        "- `toolchain.main` is reserved for the built-in generated run toolchain input and is not operator-declared inside ToolchainSet.\n"
        "- ToolchainSet is not an Operator Anchor.\n\n"
        "- use `--tolerances-ref <object_id>=<repo-relative-path>` to bind a real locked Tolerances object on the same `belgi run` spine.\n"
        f"- explicit Tolerances refs are pre-lock operator inputs. Accepted only as the current run canonical input: `{environment_root}/{RUN_ENV_TOLERANCES_FILENAME}`.\n"
        "- BELGI stages that Tolerances object into locked/store authority before C1; later stages consume the locked/store copy, not ambient workspace bytes.\n"
        "- recommended object id: `tier.tolerances`.\n"
        "- if `--tolerances-ref` is omitted, `belgi run` generates the canonical Tolerances object from the selected tier pack and locks it automatically.\n"
        "- numeric scope budgets no longer live in `IntentSpec`; move any legacy `IntentSpec.scope.max_*` values into the Tolerances object.\n"
        "- Tolerances is not an Operator Anchor.\n\n"
        "Tier requirements over the shared anchors family:\n\n"
        "- Tier-0 / Tier-1: no Operator Anchors required.\n"
        "- Tier-2: HOTL approval, pubkey refs, attestation signing ref, and exactly one seal-signing input.\n"
        "- Tier-3: the same shared Operator Anchors plus `genesis_seal` as Tier-3 evidence input outside the anchors family.\n\n"
        "Tier-2 uses the same `belgi run` backbone with explicit local-only refs:\n\n"
        "```bash\n"
        f"belgi run --repo . --tier tier-2 --intent-spec .belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md --base-revision \"${{BASE_SHA40}}\" \\\n"
        f"  --attestation-pubkey-ref env.attestation_pubkey=.belgi/runs/{run_id}/inputs/anchors/keys/attestation_pubkey.hex \\\n"
        f"  --seal-pubkey-ref env.seal_pubkey=.belgi/runs/{run_id}/inputs/anchors/keys/seal_pubkey.hex \\\n"
        f"  --hotl-approval-ref .belgi/runs/{run_id}/inputs/anchors/approvals/hotl_approval.json \\\n"
        f"  --attestation-signing-key-ref .belgi/runs/{run_id}/inputs/anchors/signing/attestation_signing_key.hex \\\n"
        f"  --seal-private-key-ref .belgi/runs/{run_id}/inputs/anchors/signing/seal_private_key.hex\n"
        "```\n\n"
        "Tier-3 stays on the same shared `belgi run` backbone:\n\n"
        "```bash\n"
        f"belgi run --repo . --tier tier-3 --intent-spec .belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md --base-revision \"${{BASE_SHA40}}\" \\\n"
        f"  --attestation-pubkey-ref env.attestation_pubkey=.belgi/runs/{run_id}/inputs/anchors/keys/attestation_pubkey.hex \\\n"
        f"  --seal-pubkey-ref env.seal_pubkey=.belgi/runs/{run_id}/inputs/anchors/keys/seal_pubkey.hex \\\n"
        f"  --hotl-approval-ref .belgi/runs/{run_id}/inputs/anchors/approvals/hotl_approval.json \\\n"
        f"  --attestation-signing-key-ref .belgi/runs/{run_id}/inputs/anchors/signing/attestation_signing_key.hex \\\n"
        f"  --seal-private-key-ref .belgi/runs/{run_id}/inputs/anchors/signing/seal_private_key.hex \\\n"
        f"  --genesis-seal-ref .belgi/runs/{run_id}/inputs/evidence/genesis_seal.json\n"
        "```\n\n"
        "7. Verify and triage:\n\n"
        "```bash\n"
        "belgi verify --repo .\n"
        "```\n\n"
        "`belgi verify` replays stored run outputs and never regenerates missing Operator Anchors, Tier-3 evidence inputs, or signatures.\n\n"
        "Artifacts are created under `.belgi/store/runs/<run_key>/<attempt_id>/`.\n"
    )

def _write_text_template(path: Path, payload: str, *, force: bool) -> str | None:
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
    inputs_dir = run_dir / RUN_INPUTS_DIRNAME
    anchors_dir = inputs_dir / RUN_ANCHORS_DIRNAME
    approvals_dir = anchors_dir / RUN_ANCHORS_APPROVALS_DIRNAME
    keys_dir = anchors_dir / RUN_ANCHORS_KEYS_DIRNAME
    signing_dir = anchors_dir / RUN_ANCHORS_SIGNING_DIRNAME
    evidence_dir = inputs_dir / RUN_EVIDENCE_DIRNAME
    environment_dir = inputs_dir / RUN_ENVIRONMENT_DIRNAME
    intent_path = _run_intent_path(run_dir)
    waivers_dir = _run_waivers_dir(run_dir)
    runbook_template_path = run_dir / "RUN.md"
    run_key_pointer_path = _run_pointer_run_key_path(run_dir)
    last_attempt_pointer_path = _run_pointer_last_attempt_path(run_dir)
    open_verdict_pointer_path = _run_pointer_open_verdict_path(run_dir)
    open_evidence_pointer_path = _run_pointer_open_evidence_path(run_dir)
    legacy_placeholder_paths = (
        run_dir / "tolerances.json",
        run_dir / "toolchain.json",
    )

    created: list[Path] = []
    updated: list[Path] = []

    if inputs_dir.exists():
        if inputs_dir.is_symlink() or not inputs_dir.is_dir():
            raise ValueError(f"invalid path in run workspace: {inputs_dir}")
    else:
        inputs_dir.mkdir(parents=True, exist_ok=True)
        created.append(inputs_dir)
    for anchor_dir in (anchors_dir, approvals_dir, keys_dir, signing_dir, evidence_dir, environment_dir):
        if anchor_dir.exists():
            if anchor_dir.is_symlink() or not anchor_dir.is_dir():
                raise ValueError(f"invalid path in run workspace: {anchor_dir}")
        else:
            anchor_dir.mkdir(parents=True, exist_ok=True)
            created.append(anchor_dir)

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

    if waivers_dir.exists():
        if waivers_dir.is_symlink() or not waivers_dir.is_dir():
            raise ValueError(f"invalid path in run workspace: {waivers_dir}")
    else:
        waivers_dir.mkdir(parents=True, exist_ok=True)
        created.append(waivers_dir)

    runbook_state = _write_text_template(runbook_template_path, _render_runbook_template(run_id=run_id), force=force)
    if runbook_state == "created":
        created.append(runbook_template_path)
    elif runbook_state == "updated":
        updated.append(runbook_template_path)

    if force:
        for legacy_path in legacy_placeholder_paths:
            if not legacy_path.exists():
                continue
            if legacy_path.is_symlink() or not legacy_path.is_file():
                raise ValueError(f"invalid path in run workspace: {legacy_path}")
            legacy_path.unlink()
            updated.append(legacy_path)

    pointer_payloads = (
        (run_key_pointer_path, "PENDING\n"),
        (last_attempt_pointer_path, "PENDING\n"),
        (open_verdict_pointer_path, "PENDING\n"),
        (open_evidence_pointer_path, "PENDING\n"),
    )
    for pointer_path, payload in pointer_payloads:
        pointer_state = _write_text_template(pointer_path, payload, force=force)
        if pointer_state == "created":
            created.append(pointer_path)
        elif pointer_state == "updated":
            updated.append(pointer_path)

    seeded_paths = [
        intent_path,
        waivers_dir,
        evidence_dir,
        runbook_template_path,
        run_key_pointer_path,
        last_attempt_pointer_path,
        open_verdict_pointer_path,
        open_evidence_pointer_path,
    ]
    return created, updated, seeded_paths

def cmd_run_new(args: argparse.Namespace) -> int:
    from belgi.core.jail import safe_relpath

    repo_root = Path(str(args.repo)).resolve()
    migrated_keys: list[str] = []
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
        runs_dir = workspace_dir / "runs"
        store_runs_dir = _resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=False)
        migrated_keys = _migrate_legacy_run_key_dirs(
            workspace_runs_dir=runs_dir,
            store_runs_dir=store_runs_dir,
            repo_root=repo_root,
        )
        run_id = _validate_run_id(str(args.run_id))
        force = bool(getattr(args, "force", False))

        template_path = workspace_dir / "templates" / "IntentSpec.core.template.md"
        if not template_path.exists() or not template_path.is_file() or template_path.is_symlink():
            raise ValueError(
                f"missing workspace template; run `belgi init --repo . --workspace {workspace_rel}` first"
            )
        template_bytes = template_path.read_bytes()

        run_dir = runs_dir / run_id
        if run_dir.exists() and (run_dir.is_symlink() or not run_dir.is_dir()):
            raise ValueError(f"invalid run workspace path: {run_dir}")
        run_dir.mkdir(parents=True, exist_ok=True)

        created, updated, seeded_paths = _seed_run_workspace(
            run_dir=run_dir,
            run_id=run_id,
            intent_bytes=template_bytes,
            force=force,
        )

    except Exception as e:
        print(f"[belgi run new] ERROR: {e}", file=sys.stderr)
        return 3

    _ = (created, updated, seeded_paths)
    print(f"[belgi run new] summary: run={run_id} workspace={workspace_rel}", file=sys.stderr)
    if migrated_keys:
        print(f"[belgi run new] migrated_legacy_keys: {len(migrated_keys)}", file=sys.stderr)

    open_targets: list[tuple[str, Path]] = [
        ("runbook", run_dir / "RUN.md"),
        ("intent", _run_intent_path(run_dir)),
        ("waivers", _run_waivers_dir(run_dir)),
    ]
    family = _platform_family()
    print("[belgi run new] open:", file=sys.stderr)
    for label, target_path in open_targets:
        rel = safe_relpath(repo_root, target_path)
        platform_name, cmd = _open_command_for_platform(path=target_path.resolve(), family=family)
        print(f"[belgi run new]   {label}: {rel}", file=sys.stderr)
        print(f"[belgi run new]     open_{platform_name}: {cmd}", file=sys.stderr)
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

def _load_adversarial_signal_from_policy_report(policy_report_path: Path) -> tuple[bool, int]:
    try:
        payload = json.loads(policy_report_path.read_text(encoding="utf-8", errors="strict"))
    except Exception as e:
        raise ValueError(f"policy.adversarial_scan.json is not valid UTF-8 JSON: {e}") from e
    if not isinstance(payload, dict):
        raise ValueError("policy.adversarial_scan.json must be a JSON object")

    finding_count_raw = payload.get("finding_count")
    if not isinstance(finding_count_raw, int) or isinstance(finding_count_raw, bool) or finding_count_raw < 0:
        raise ValueError("policy.adversarial_scan finding_count missing/invalid")
    findings_present_raw = payload.get("findings_present")
    if findings_present_raw is None:
        findings_present = finding_count_raw > 0
    elif isinstance(findings_present_raw, bool):
        findings_present = findings_present_raw
    else:
        raise ValueError("policy.adversarial_scan findings_present missing/invalid")
    if findings_present != (finding_count_raw > 0):
        raise ValueError("policy.adversarial_scan findings_present inconsistent with finding_count")
    return findings_present, finding_count_raw

def _load_next_instruction_from_gate_verdict(path: Path) -> str | None:
    if not path.exists() or path.is_symlink() or not path.is_file():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    expected_gate = _gate_letter_from_verdict_path(path)
    if expected_gate is None:
        return None
    gate_id = obj.get("gate_id")
    if not isinstance(gate_id, str) or gate_id.strip() != expected_gate:
        return None
    verdict = obj.get("verdict")
    if not isinstance(verdict, str) or verdict.strip() != "NO-GO":
        return None
    remediation = obj.get("remediation")
    if not isinstance(remediation, dict):
        return None
    next_instruction = remediation.get("next_instruction")
    if not isinstance(next_instruction, str) or not next_instruction.strip():
        return None
    return next_instruction.strip()

def _load_next_instruction_from_c1_parse_diagnostic(chain_out_dir: Path | None) -> str | None:
    if chain_out_dir is None:
        return None
    diag_path = chain_out_dir / "C1IntentParseError.json"
    if not diag_path.exists() or diag_path.is_symlink() or not diag_path.is_file():
        return None
    try:
        obj = json.loads(diag_path.read_text(encoding="utf-8", errors="strict"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    next_instruction = obj.get("next_instruction")
    if not isinstance(next_instruction, str) or not next_instruction.strip():
        return None
    return next_instruction.strip()

def _preferred_gate_verdict_order(primary_reason: str | None) -> tuple[str, ...]:
    reason = str(primary_reason or "").lower()
    if "gate_q" in reason:
        return ("GateVerdict.Q.json", "GateVerdict.R.json", "GateVerdict.S.json")
    if "gate_r" in reason:
        return ("GateVerdict.R.json", "GateVerdict.Q.json", "GateVerdict.S.json")
    if "gate_s" in reason:
        return ("GateVerdict.S.json", "GateVerdict.R.json", "GateVerdict.Q.json")
    return ("GateVerdict.R.json", "GateVerdict.Q.json", "GateVerdict.S.json")

def _gate_letter_from_verdict_name(name: str) -> str | None:
    m = re.fullmatch(r"GateVerdict\.([QRS])\.json", str(name or ""))
    if m is None:
        return None
    return str(m.group(1))

def _gate_letter_from_verdict_path(path: Path | None) -> str | None:
    if path is None:
        return None
    return _gate_letter_from_verdict_name(path.name)

def _gate_verdict_paths(chain_out_dir: Path | None) -> dict[str, Path | None]:
    out: dict[str, Path | None] = {"Q": None, "R": None, "S": None}
    if chain_out_dir is None:
        return out
    for gate in ("Q", "R", "S"):
        p = chain_out_dir / f"GateVerdict.{gate}.json"
        if p.exists() and not p.is_symlink() and p.is_file():
            out[gate] = p
    return out

def _gate_verdict_outcome(path: Path) -> str | None:
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    raw = obj.get("verdict")
    if not isinstance(raw, str):
        return None
    verdict = raw.strip()
    if verdict in {"GO", "NO-GO"}:
        return verdict
    return None

def _gate_status_map(gate_paths: dict[str, Path | None]) -> dict[str, str]:
    out: dict[str, str] = {}
    for gate in ("Q", "R", "S"):
        p = gate_paths.get(gate)
        if p is None:
            out[gate] = "missing"
            continue
        outcome = _gate_verdict_outcome(p)
        out[gate] = outcome if outcome is not None else "present"
    return out

def _primary_gate_verdict_path(chain_out_dir: Path | None, *, primary_reason: str | None = None) -> Path | None:
    if chain_out_dir is None:
        return None
    for name in _preferred_gate_verdict_order(primary_reason):
        p = chain_out_dir / name
        if p.exists() and not p.is_symlink() and p.is_file():
            return p
    return None

def _run_no_go_next_instruction(*, chain_out_dir: Path | None, primary_reason: str) -> str:
    if chain_out_dir is not None:
        for gate_name in _preferred_gate_verdict_order(primary_reason):
            next_instruction = _load_next_instruction_from_gate_verdict(chain_out_dir / gate_name) or ""
            if next_instruction:
                return next_instruction
        parse_next_instruction = _load_next_instruction_from_c1_parse_diagnostic(chain_out_dir)
        if parse_next_instruction:
            return parse_next_instruction
    return _RUN_NO_GO_GENERIC_NEXT

def _evidence_manifest_path(chain_out_dir: Path | None) -> Path | None:
    if chain_out_dir is None:
        return None
    return chain_out_dir / "EvidenceManifest.json"

def _env_truthy(name: str) -> bool:
    raw = str(os.environ.get(name, "") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}

def _hyperlinks_enabled() -> bool:
    return _env_truthy("BELGI_HYPERLINKS") and cli_render._stderr_supports_color()

def _contains_control_chars(raw: str) -> bool:
    return any((ord(ch) < 32 or ord(ch) == 127) for ch in raw)

def _safe_file_uri(path: Path) -> str | None:
    try:
        resolved = path.resolve()
    except Exception:
        return None
    raw = str(resolved)
    if _contains_control_chars(raw):
        return None
    try:
        uri = resolved.as_uri()
    except Exception:
        return None
    if not uri.startswith("file://"):
        return None
    return uri

def _osc8_link(*, label: str, path: Path) -> str | None:
    uri = _safe_file_uri(path)
    if uri is None:
        return None
    if _contains_control_chars(label):
        return None
    esc = "\x1b"
    st = f"{esc}\\"
    return f"{esc}]8;;{uri}{st}{label}{esc}]8;;{st}"

def _quote_double(raw: str) -> str:
    return '"' + raw.replace("\\", "\\\\").replace('"', '\\"') + '"'

def _quote_powershell_single(raw: str) -> str:
    return "'" + raw.replace("'", "''") + "'"

def _open_command_lines(*, path: Path) -> tuple[str, str, str]:
    resolved = str(path.resolve())
    posix = _quote_double(resolved)
    pwsh = _quote_powershell_single(resolved)
    return (
        f"open {posix}",
        f"xdg-open {posix}",
        f"powershell -NoProfile -Command \"Start-Process -FilePath {pwsh}\"",
    )

def _platform_family() -> str:
    plat = str(sys.platform or "").lower()
    if plat.startswith("darwin"):
        return "macos"
    if plat.startswith("win"):
        return "windows"
    return "linux"

def _show_all_open_helpers(*, verbose: bool) -> bool:
    return bool(verbose) or _env_truthy("BELGI_SHOW_ALL_OPEN")

def _open_command_for_platform(*, path: Path, family: str | None = None) -> tuple[str, str]:
    mac, linux, windows = _open_command_lines(path=path)
    fam = family or _platform_family()
    if fam == "macos":
        return "macos", mac
    if fam == "windows":
        return "windows", windows
    return "linux", linux

def _repo_rel_display(repo_root: Path, path: Path) -> str | None:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except Exception:
        return None

def _short_run_key(run_key: str | None) -> str | None:
    if not run_key:
        return None
    return run_key[:10]

def _short_attempt_id(attempt_id: str | None) -> str | None:
    if not attempt_id:
        return None
    m = ATTEMPT_ID_PATTERN.fullmatch(str(attempt_id))
    if m is None:
        return attempt_id
    return m.group(1)

def _best_waiver_open_target(
    *,
    run_workspace_dir: Path | None,
    open_paths: list[Path],
) -> Path | None:
    if run_workspace_dir is not None:
        waivers_dir = _run_waivers_dir(run_workspace_dir)
        if waivers_dir.exists() and waivers_dir.is_dir() and not waivers_dir.is_symlink():
            return waivers_dir
    for p in open_paths:
        rel = p.as_posix()
        if "/waivers/" in rel or rel.endswith("/waivers_applied.json"):
            return p
    return None

def _run_workspace_pointer_targets(run_workspace_dir: Path | None) -> tuple[Path | None, Path | None]:
    if run_workspace_dir is None:
        return None, None
    verdict_ptr = _run_pointer_open_verdict_path(run_workspace_dir)
    evidence_ptr = _run_pointer_open_evidence_path(run_workspace_dir)
    out_verdict = verdict_ptr if verdict_ptr.exists() and verdict_ptr.is_file() and not verdict_ptr.is_symlink() else None
    out_evidence = evidence_ptr if evidence_ptr.exists() and evidence_ptr.is_file() and not evidence_ptr.is_symlink() else None
    return out_verdict, out_evidence

def _write_run_workspace_pointers(
    *,
    repo_root: Path,
    run_workspace_dir: Path | None,
    run_key: str | None,
    attempt_id: str | None,
    chain_out_dir: Path | None,
) -> None:
    from belgi.core.jail import safe_relpath

    if run_workspace_dir is None or run_key is None or attempt_id is None:
        return

    gate_verdict_path = _primary_gate_verdict_path(chain_out_dir)
    evidence_path = _evidence_manifest_path(chain_out_dir)
    gate_verdict_rel = safe_relpath(repo_root, gate_verdict_path) if gate_verdict_path is not None else "PENDING"
    evidence_rel = safe_relpath(repo_root, evidence_path) if evidence_path is not None else "PENDING"

    _write_text(_run_pointer_run_key_path(run_workspace_dir), f"{run_key}\n")
    _write_text(_run_pointer_last_attempt_path(run_workspace_dir), f"{attempt_id}\n")
    _write_text(_run_pointer_open_verdict_path(run_workspace_dir), f"{gate_verdict_rel}\n")
    _write_text(_run_pointer_open_evidence_path(run_workspace_dir), f"{evidence_rel}\n")

def _emit_run_failure_links(
    *,
    repo_root: Path,
    level: str,
    tier_id: str | None,
    run_ref: str | None,
    run_key: str | None,
    attempt_id: str | None,
    primary_reason: str,
    remediation_next_instruction: str,
    chain_out_dir: Path | None,
    gate_verdict_path: Path | None,
    evidence_manifest_path: Path | None,
    run_workspace_dir: Path | None,
    open_paths: list[Path],
    verbose: bool,
) -> None:
    family = _platform_family()
    show_all_open = _show_all_open_helpers(verbose=verbose)
    run_tokens = ["verdict=NO-GO", f"tier={tier_id or 'UNKNOWN'}"]
    if run_ref:
        run_tokens.append(f"run={run_ref}")
    run_tokens.append(f"key={_short_run_key(run_key) or 'UNKNOWN'}")
    run_tokens.append(f"attempt={_short_attempt_id(attempt_id) or 'UNKNOWN'}")
    gate_paths = _gate_verdict_paths(chain_out_dir)
    primary_gate = _gate_letter_from_verdict_path(gate_verdict_path)
    if primary_gate is None:
        primary_gate = _gate_letter_from_verdict_name(_preferred_gate_verdict_order(primary_reason)[0]) or "R"
    gate_status = _gate_status_map(gate_paths)
    next_instruction = str(remediation_next_instruction or "").strip()
    if not next_instruction:
        next_instruction = _RUN_NO_GO_GENERIC_NEXT
    lines = [
        "summary: " + " ".join(run_tokens),
        "",
        f"cause: {primary_reason}",
        f"next: {next_instruction}",
        "",
        "evidence:",
        f"  gate: {primary_gate}",
        f"  gate_status: Q={gate_status['Q']} R={gate_status['R']} S={gate_status['S']}",
    ]

    verdict_ptr, evidence_ptr = _run_workspace_pointer_targets(run_workspace_dir)

    if gate_verdict_path is not None:
        if verdict_ptr is not None and not verbose:
            verdict_rel = _repo_rel_display(repo_root, verdict_ptr.resolve()) or str(verdict_ptr.resolve())
            lines.append(f"  verdict: {verdict_rel}")
        else:
            gate_rel = _repo_rel_display(repo_root, gate_verdict_path.resolve()) or str(gate_verdict_path.resolve())
            lines.append(f"  verdict: {gate_rel}")
        if verbose:
            lines.append(f"  verdict_store_path: {gate_verdict_path.resolve()}")
    else:
        lines.append("  verdict: unavailable (no GateVerdict file produced)")

    evidence_present = (
        evidence_manifest_path is not None
        and evidence_manifest_path.exists()
        and evidence_manifest_path.is_file()
        and not evidence_manifest_path.is_symlink()
    )
    if evidence_present and evidence_manifest_path is not None:
        lines.append("  manifest: present")
        if verbose:
            lines.append(f"  manifest_path: {evidence_manifest_path.resolve()}")
    else:
        lines.append("  manifest: missing")
    if verbose:
        for gate in ("Q", "R", "S"):
            p = gate_paths[gate]
            if p is not None:
                lines.append(f"  verdict_{gate}_path: {p.resolve()}")

    intent_target: Path | None = None
    for path in open_paths:
        if path.name == "IntentSpec.core.md":
            intent_target = path
            break
    waiver_target = _best_waiver_open_target(run_workspace_dir=run_workspace_dir, open_paths=open_paths)
    verdict_display_target = verdict_ptr if (verdict_ptr is not None and not verbose) else gate_verdict_path

    targets: list[tuple[str, Path, Path]] = []
    if gate_verdict_path is not None and verdict_display_target is not None:
        targets.append((f"verdict_{primary_gate}", verdict_display_target, gate_verdict_path))
    if intent_target is not None:
        targets.append(("intent", intent_target, intent_target))
    if waiver_target is not None:
        targets.append(("waivers", waiver_target, waiver_target))
    if verbose and evidence_present and evidence_ptr is not None:
        targets.append(("manifest", evidence_ptr, evidence_ptr))

    lines.append("")
    lines.append("open:")
    seen_target: set[str] = set()
    for label, display_path, open_path in targets:
        display_resolved = display_path.resolve()
        open_resolved = open_path.resolve()
        key = f"{label}:{display_resolved}:{open_resolved}"
        if key in seen_target:
            continue
        seen_target.add(key)
        rel = _repo_rel_display(repo_root, display_resolved) or str(display_resolved)
        display_label = label
        if _hyperlinks_enabled():
            maybe_link = _osc8_link(label=label, path=open_resolved)
            if maybe_link is not None:
                display_label = maybe_link

        if show_all_open:
            mac, linux, windows = _open_command_lines(path=open_resolved)
            lines.append(f"  {display_label}: {rel}")
            lines.append(f"    open_macos: {mac}")
            lines.append(f"    open_linux: {linux}")
            lines.append(f"    open_windows: {windows}")
            continue

        platform_name, cmd = _open_command_for_platform(path=open_resolved, family=family)
        lines.append(f"  {display_label}: {rel}")
        lines.append(f"    open_{platform_name}: {cmd}")

    if verbose:
        lines.append("")
        lines.append("details:")
        if run_key is not None:
            lines.append(f"  run_key: {run_key}")
        if attempt_id is not None:
            lines.append(f"  attempt_id: {attempt_id}")
        if gate_verdict_path is not None:
            lines.append(f"  gate_verdict_path: {gate_verdict_path.resolve()}")
        if evidence_manifest_path is not None:
            lines.append(f"  evidence_manifest_path: {evidence_manifest_path.resolve()}")

    cli_render._emit_human_status(prefix="[belgi run]", level=level, lines=lines)

def _emit_run_success_links(
    *,
    repo_root: Path,
    tier_id: str | None,
    run_ref: str | None,
    run_key: str | None,
    attempt_id: str | None,
    run_workspace_dir: Path | None,
    chain_out_dir: Path | None,
    chain_repo_dir: Path | None,
    intent_open_path: Path | None,
    verbose: bool,
) -> None:
    family = _platform_family()
    show_all_open = _show_all_open_helpers(verbose=verbose)
    run_tokens = ["verdict=GO", f"tier={tier_id or 'UNKNOWN'}"]
    if run_ref:
        run_tokens.append(f"run={run_ref}")
    run_tokens.append(f"key={_short_run_key(run_key) or 'UNKNOWN'}")
    run_tokens.append(f"attempt={_short_attempt_id(attempt_id) or 'UNKNOWN'}")

    gate_r_path: Path | None = None
    manifest_path: Path | None = None
    seal_path: Path | None = None
    if chain_out_dir is not None:
        maybe_r = chain_out_dir / "GateVerdict.R.json"
        if maybe_r.exists() and maybe_r.is_file() and not maybe_r.is_symlink():
            gate_r_path = maybe_r
        maybe_manifest = chain_out_dir / "EvidenceManifest.json"
        if maybe_manifest.exists() and maybe_manifest.is_file() and not maybe_manifest.is_symlink():
            manifest_path = maybe_manifest
        maybe_seal = chain_out_dir / "SealManifest.json"
        if maybe_seal.exists() and maybe_seal.is_file() and not maybe_seal.is_symlink():
            seal_path = maybe_seal

    verdict_ptr, evidence_ptr = _run_workspace_pointer_targets(run_workspace_dir)
    verdict_display = verdict_ptr if (verdict_ptr is not None and not verbose) else gate_r_path
    manifest_display = evidence_ptr if (evidence_ptr is not None and not verbose) else manifest_path

    if intent_open_path is not None and intent_open_path.exists() and intent_open_path.is_file() and not intent_open_path.is_symlink():
        intent_target: Path | None = intent_open_path
    elif chain_repo_dir is not None:
        maybe_intent = chain_repo_dir / "IntentSpec.core.md"
        intent_target = maybe_intent if maybe_intent.exists() and maybe_intent.is_file() and not maybe_intent.is_symlink() else None
    else:
        intent_target = None

    waivers_target: Path | None = None
    if run_workspace_dir is not None:
        maybe_waivers = _run_waivers_dir(run_workspace_dir)
        if maybe_waivers.exists() and maybe_waivers.is_dir() and not maybe_waivers.is_symlink():
            waivers_target = maybe_waivers
    if waivers_target is None and chain_repo_dir is not None:
        maybe_waivers_applied = chain_repo_dir / "out" / "inputs" / "waivers_applied"
        if maybe_waivers_applied.exists() and maybe_waivers_applied.is_file() and not maybe_waivers_applied.is_symlink():
            waivers_target = maybe_waivers_applied
        else:
            maybe_inputs = chain_repo_dir / "out" / "inputs"
            if maybe_inputs.exists() and maybe_inputs.is_dir() and not maybe_inputs.is_symlink():
                waivers_target = maybe_inputs

    lines = [
        "summary: " + " ".join(run_tokens),
        "",
        "evidence:",
    ]

    if verdict_display is not None:
        verdict_rel = _repo_rel_display(repo_root, verdict_display.resolve()) or str(verdict_display.resolve())
        lines.append(f"  verdict_R: {verdict_rel}")
    else:
        lines.append("  verdict_R: missing")

    if manifest_display is not None:
        manifest_rel = _repo_rel_display(repo_root, manifest_display.resolve()) or str(manifest_display.resolve())
        lines.append(f"  manifest: {manifest_rel}")
    else:
        lines.append("  manifest: missing")

    if seal_path is not None:
        seal_rel = _repo_rel_display(repo_root, seal_path.resolve()) or str(seal_path.resolve())
        lines.append(f"  seal: {seal_rel}")
    else:
        lines.append("  seal: missing")

    lines.append("")
    lines.append("open:")

    targets: list[tuple[str, Path, Path]] = []
    if gate_r_path is not None and verdict_display is not None:
        targets.append(("verdict_R", verdict_display, gate_r_path))
    if manifest_path is not None and manifest_display is not None:
        targets.append(("manifest", manifest_display, manifest_path))
    if intent_target is not None:
        targets.append(("intent", intent_target, intent_target))
    if waivers_target is not None:
        targets.append(("waivers", waivers_target, waivers_target))

    seen_target: set[str] = set()
    for label, display_path, open_path in targets:
        display_resolved = display_path.resolve()
        open_resolved = open_path.resolve()
        key = f"{label}:{display_resolved}:{open_resolved}"
        if key in seen_target:
            continue
        seen_target.add(key)
        rel = _repo_rel_display(repo_root, display_resolved) or str(display_resolved)
        display_label = label
        if _hyperlinks_enabled():
            maybe_link = _osc8_link(label=label, path=open_resolved)
            if maybe_link is not None:
                display_label = maybe_link

        if show_all_open:
            mac, linux, windows = _open_command_lines(path=open_resolved)
            lines.append(f"  {display_label}: {rel}")
            lines.append(f"    open_macos: {mac}")
            lines.append(f"    open_linux: {linux}")
            lines.append(f"    open_windows: {windows}")
            continue

        platform_name, cmd = _open_command_for_platform(path=open_resolved, family=family)
        lines.append(f"  {display_label}: {rel}")
        lines.append(f"    open_{platform_name}: {cmd}")

    if verbose:
        lines.append("")
        lines.append("details:")
        if run_key is not None:
            lines.append(f"  run_key: {run_key}")
        if attempt_id is not None:
            lines.append(f"  attempt_id: {attempt_id}")
        if gate_r_path is not None:
            lines.append(f"  verdict_R_path: {gate_r_path.resolve()}")
        if manifest_path is not None:
            lines.append(f"  manifest_path: {manifest_path.resolve()}")
        if seal_path is not None:
            lines.append(f"  seal_path: {seal_path.resolve()}")

    cli_render._emit_human_status(prefix="[belgi run]", level="GO", lines=lines)

def _write_run_summary_if_ready(
    *,
    repo_root: Path,
    summary_path: Path | None,
    run_key: str | None,
    attempt_id: str | None,
    tier_id: str | None,
    workspace_rel: str | None,
    run_key_dir: Path | None,
    attempt_dir: Path | None,
    run_key_preimage: dict[str, object] | None,
    chain_repo_dir: Path | None,
    chain_out_dir: Path | None,
    chain_paths: list[Path],
    adversarial_findings_present: bool,
    adversarial_findings_count: int,
    waivers_applied_count: int,
    waivers_applied_refs: list[str],
    verdict: str,
    primary_reason: str,
) -> bool:
    from belgi.core.jail import safe_relpath

    if summary_path is None:
        return False
    if not run_key or not attempt_id:
        return False
    if workspace_rel is None or run_key_dir is None or attempt_dir is None:
        return False

    artifacts = _build_artifact_entries(repo_root, paths=chain_paths) if chain_paths else []
    summary_obj: dict[str, object] = {
        "schema_version": "1.0.0",
        "summary_kind": "belgi_run_attempt",
        "run_key": run_key,
        "attempt_id": attempt_id,
        "tier_id": tier_id,
        "workspace_root": workspace_rel,
        "run_root": safe_relpath(repo_root, run_key_dir),
        "attempt_root": safe_relpath(repo_root, attempt_dir),
        "run_key_preimage": run_key_preimage if isinstance(run_key_preimage, dict) else {},
        "chain_repo_root": safe_relpath(repo_root, chain_repo_dir) if chain_repo_dir is not None else None,
        "chain_output_root": safe_relpath(repo_root, chain_out_dir) if chain_out_dir is not None else None,
        "adversarial_scan": {
            "findings_present": adversarial_findings_present,
            "finding_count": adversarial_findings_count,
        },
        "waivers_applied": {
            "count": int(waivers_applied_count),
            "storage_refs": list(waivers_applied_refs),
        },
        "verdict": verdict,
        "primary_reason": str(primary_reason),
        "artifacts": artifacts,
    }
    _write_json(summary_path, summary_obj)
    return True

def _load_json_object(path: Path, *, label: str) -> dict[str, object]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception as e:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"{label} must be a JSON object")
    return obj

def _parse_object_ref_cli(raw: str, *, flag_name: str) -> tuple[str, str]:
    spec = str(raw or "").strip()
    if not spec:
        raise _UserInputError(f"{flag_name} missing/invalid")
    if "=" not in spec:
        raise _UserInputError(f"{flag_name} must use <object_id>=<repo-relative-path>")
    object_id, storage_ref = spec.split("=", 1)
    object_id = object_id.strip()
    storage_ref = storage_ref.strip()
    if not object_id or not storage_ref:
        raise _UserInputError(f"{flag_name} must use <object_id>=<repo-relative-path>")
    return object_id, storage_ref

def _resolve_local_input_file_ref(
    repo_root: Path,
    *,
    raw: str,
    flag_name: str,
    required_suffix: str | None = None,
) -> tuple[str, Path]:
    from belgi.core.jail import resolve_repo_rel_path, safe_relpath

    ref = str(raw or "").strip()
    if not ref:
        raise _UserInputError(f"{flag_name} missing/invalid")
    try:
        path = resolve_repo_rel_path(
            repo_root,
            ref,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
    except ValueError as e:
        raise _UserInputError(str(e)) from e
    if required_suffix is not None and path.suffix.lower() != required_suffix.lower():
        raise _UserInputError(f"{flag_name} must point to a {required_suffix} file")
    return safe_relpath(repo_root, path), path


def _assert_evaluated_revision_visible_storage_ref(
    *,
    repo_root: Path,
    resolved_storage_ref: str,
    flag_name: str,
    evaluated_revision: str,
) -> None:
    cp = subprocess.run(
        ["git", "-C", str(repo_root), "ls-tree", "-r", "--name-only", evaluated_revision, "--", resolved_storage_ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if cp.returncode != 0:
        stderr = str(cp.stderr or "").strip()
        raise _UserInputError(
            f"cannot resolve {flag_name} against evaluated revision: {stderr or 'git ls-tree failed'}"
        )
    visible_paths = {line.strip() for line in cp.stdout.splitlines() if line.strip()}
    if resolved_storage_ref not in visible_paths:
        raise _UserInputError(
            f"{flag_name} must point to a repo-relative file present in the evaluated revision: "
            f"{resolved_storage_ref}"
        )


def _resolve_evaluated_revision_visible_file_ref(
    *,
    repo_root: Path,
    raw: str,
    flag_name: str,
    evaluated_revision: str,
) -> tuple[str, Path]:
    resolved_storage_ref, storage_path = _resolve_local_input_file_ref(
        repo_root,
        raw=raw,
        flag_name=flag_name,
    )
    _assert_evaluated_revision_visible_storage_ref(
        repo_root=repo_root,
        resolved_storage_ref=resolved_storage_ref,
        flag_name=flag_name,
        evaluated_revision=evaluated_revision,
    )
    return resolved_storage_ref, storage_path


def _canonical_run_environment_object_ref(*, workspace_rel: str, run_id: str, leaf_name: str) -> str:
    return PurePosixPath(
        str(workspace_rel).strip(),
        "runs",
        str(run_id).strip(),
        RUN_INPUTS_DIRNAME,
        RUN_ENVIRONMENT_DIRNAME,
        leaf_name,
    ).as_posix()


def _resolve_run_environment_object_ref(
    *,
    repo_root: Path,
    workspace_rel: str,
    run_id: str | None,
    raw: str,
    flag_name: str,
    leaf_name: str,
) -> tuple[str, Path]:
    resolved_storage_ref, storage_path = _resolve_local_input_file_ref(
        repo_root,
        raw=raw,
        flag_name=flag_name,
        required_suffix=".json",
    )
    if run_id is None:
        raise _UserInputError(
            f"{flag_name} requires a current run intent at "
            f"{workspace_rel}/runs/<run_id>/{RUN_INTENT_REPO_REL}"
        )
    expected_storage_ref = _canonical_run_environment_object_ref(
        workspace_rel=workspace_rel,
        run_id=run_id,
        leaf_name=leaf_name,
    )
    if resolved_storage_ref != expected_storage_ref:
        raise _UserInputError(
            f"{flag_name} must point to the current run canonical input: {expected_storage_ref}"
        )
    return resolved_storage_ref, storage_path

def _validate_hotl_approval_input(*, hotl_path: Path) -> None:
    from belgi.core.schema import validate_schema
    from belgi.protocol.pack import get_builtin_protocol_context

    hotl_obj = _load_json_object(hotl_path, label="HOTL approval artifact")
    protocol = get_builtin_protocol_context()
    hotl_schema = protocol.read_json("schemas/HOTLApproval.schema.json")
    if not isinstance(hotl_schema, dict):
        raise _UserInputError("builtin HOTLApproval schema missing/invalid")
    errs = validate_schema(hotl_obj, hotl_schema, root_schema=hotl_schema, path="HOTLApproval")
    if errs:
        first = errs[0]
        raise _UserInputError(f"--hotl-approval-ref invalid at {first.path}: {first.message}")

def _validate_genesis_seal_input(*, genesis_seal_path: Path) -> None:
    from belgi.trust_anchor import TrustAnchorError, validate_genesis_seal_schema

    genesis_obj = _load_json_object(genesis_seal_path, label="genesis_seal artifact")
    try:
        validate_genesis_seal_schema(genesis_obj, source="genesis_seal")
    except TrustAnchorError as e:
        raise _UserInputError(f"--genesis-seal-ref invalid: {e}") from e

def _shared_operator_anchor_missing_flags(args: argparse.Namespace) -> list[str]:
    raw_args = {
        name: str(getattr(args, name, "") or "").strip()
        for name in (
            "attestation_pubkey_ref",
            "seal_pubkey_ref",
            "hotl_approval_ref",
            "attestation_signing_key_ref",
            "seal_private_key_ref",
            "seal_signature_ref",
        )
    }
    missing_required = [
        flag_name
        for flag_name in (
            "--attestation-pubkey-ref",
            "--seal-pubkey-ref",
            "--hotl-approval-ref",
            "--attestation-signing-key-ref",
        )
        if not raw_args[flag_name[2:].replace("-", "_")]
    ]
    if not raw_args["seal_private_key_ref"] and not raw_args["seal_signature_ref"]:
        missing_required.append("--seal-private-key-ref or --seal-signature-ref")
    return missing_required

def _tier3_missing_input_reason(args: argparse.Namespace) -> str | None:
    missing_anchor_flags = _shared_operator_anchor_missing_flags(args)
    missing_genesis = not str(getattr(args, "genesis_seal_ref", "") or "").strip()
    if not missing_anchor_flags and not missing_genesis:
        return None
    parts: list[str] = []
    if missing_anchor_flags:
        parts.append("tier-3 requires Operator Anchors: " + ", ".join(missing_anchor_flags))
    if missing_genesis:
        parts.append("tier-3 requires Tier-3 evidence input: --genesis-seal-ref")
    return "; ".join(parts)

def _resolve_shared_operator_anchors(
    *,
    repo_root: Path,
    args: argparse.Namespace,
    tier_id: str,
) -> tuple[OperatorAnchorInputs | None, list[Path]]:
    anchor_arg_names = (
        "attestation_pubkey_ref",
        "seal_pubkey_ref",
        "hotl_approval_ref",
        "attestation_signing_key_ref",
        "seal_private_key_ref",
        "seal_signature_ref",
    )
    raw_args = {name: str(getattr(args, name, "") or "").strip() for name in anchor_arg_names}
    has_any_anchor = any(raw_args.values())

    if tier_id not in {"tier-2", "tier-3"}:
        if has_any_anchor:
            raise _UserInputError("operator anchor refs are allowed only with --tier tier-2 or --tier tier-3")
        return None, []

    missing_required = _shared_operator_anchor_missing_flags(args)
    if raw_args["seal_private_key_ref"] and raw_args["seal_signature_ref"]:
        raise _UserInputError(
            f"{tier_id} requires exactly one seal signing anchor: use --seal-private-key-ref or --seal-signature-ref"
        )
    if missing_required:
        raise _UserInputError(f"{tier_id} requires Operator Anchors: " + ", ".join(missing_required))

    attestation_pubkey_id, attestation_pubkey_ref = _parse_object_ref_cli(
        raw_args["attestation_pubkey_ref"],
        flag_name="--attestation-pubkey-ref",
    )
    seal_pubkey_id, seal_pubkey_ref = _parse_object_ref_cli(
        raw_args["seal_pubkey_ref"],
        flag_name="--seal-pubkey-ref",
    )

    _, attestation_pubkey_path = _resolve_local_input_file_ref(
        repo_root,
        raw=attestation_pubkey_ref,
        flag_name="--attestation-pubkey-ref",
    )
    _, seal_pubkey_path = _resolve_local_input_file_ref(
        repo_root,
        raw=seal_pubkey_ref,
        flag_name="--seal-pubkey-ref",
    )
    hotl_approval_ref, hotl_approval_path = _resolve_local_input_file_ref(
        repo_root,
        raw=raw_args["hotl_approval_ref"],
        flag_name="--hotl-approval-ref",
        required_suffix=".json",
    )
    _validate_hotl_approval_input(hotl_path=hotl_approval_path)
    attestation_signing_key_ref, attestation_signing_key_path = _resolve_local_input_file_ref(
        repo_root,
        raw=raw_args["attestation_signing_key_ref"],
        flag_name="--attestation-signing-key-ref",
    )

    seal_private_key_ref: str | None = None
    seal_private_key_path: Path | None = None
    if raw_args["seal_private_key_ref"]:
        seal_private_key_ref, seal_private_key_path = _resolve_local_input_file_ref(
            repo_root,
            raw=raw_args["seal_private_key_ref"],
            flag_name="--seal-private-key-ref",
        )

    seal_signature_ref: str | None = None
    seal_signature_path: Path | None = None
    if raw_args["seal_signature_ref"]:
        seal_signature_ref, seal_signature_path = _resolve_local_input_file_ref(
            repo_root,
            raw=raw_args["seal_signature_ref"],
            flag_name="--seal-signature-ref",
        )

    open_paths = [
        attestation_pubkey_path,
        seal_pubkey_path,
        hotl_approval_path,
        attestation_signing_key_path,
    ]
    if seal_private_key_path is not None:
        open_paths.append(seal_private_key_path)
    if seal_signature_path is not None:
        open_paths.append(seal_signature_path)

    return (
        OperatorAnchorInputs(
            attestation_pubkey_id=attestation_pubkey_id,
            attestation_pubkey_source_ref=attestation_pubkey_ref,
            seal_pubkey_id=seal_pubkey_id,
            seal_pubkey_source_ref=seal_pubkey_ref,
            hotl_approval_source_ref=hotl_approval_ref,
            attestation_signing_key_source_ref=attestation_signing_key_ref,
            seal_private_key_source_ref=seal_private_key_ref,
            seal_signature_source_ref=seal_signature_ref,
        ),
        open_paths,
    )

def _resolve_run_evidence_inputs(
    *,
    repo_root: Path,
    args: argparse.Namespace,
    tier_id: str,
) -> tuple[RunEvidenceInputs | None, list[Path]]:
    raw = str(getattr(args, "genesis_seal_ref", "") or "").strip()

    if tier_id != "tier-3":
        if raw:
            raise _UserInputError("Tier-3 evidence refs are allowed only with --tier tier-3")
        return None, []

    if not raw:
        raise _UserInputError("tier-3 requires evidence inputs: --genesis-seal-ref")

    genesis_seal_ref, genesis_seal_path = _resolve_local_input_file_ref(
        repo_root,
        raw=raw,
        flag_name="--genesis-seal-ref",
        required_suffix=".json",
    )
    _validate_genesis_seal_input(genesis_seal_path=genesis_seal_path)
    return RunEvidenceInputs(genesis_seal_source_ref=genesis_seal_ref), [genesis_seal_path]


def _resolve_run_toolchain_refs(
    *,
    repo_root: Path,
    args: argparse.Namespace,
    evaluated_revision: str,
) -> tuple[list[str], list[Path]]:
    raw_refs = [str(raw or "").strip() for raw in (getattr(args, "toolchain_ref", None) or [])]
    if not raw_refs:
        return [], []

    resolved_refs: list[str] = []
    open_paths: list[Path] = []
    seen_toolchain_ids: set[str] = set()

    for raw in raw_refs:
        toolchain_id, storage_ref = _parse_object_ref_cli(raw, flag_name="--toolchain-ref")
        if toolchain_id == "toolchain.main":
            raise _UserInputError("--toolchain-ref id `toolchain.main` is reserved for the built-in run toolchain input")
        if toolchain_id in seen_toolchain_ids:
            raise _UserInputError(f"duplicate toolchain id: {toolchain_id}")
        seen_toolchain_ids.add(toolchain_id)
        resolved_storage_ref, storage_path = _resolve_evaluated_revision_visible_file_ref(
            repo_root=repo_root,
            raw=storage_ref,
            flag_name="--toolchain-ref",
            evaluated_revision=evaluated_revision,
        )
        resolved_refs.append(f"{toolchain_id}={resolved_storage_ref}")
        open_paths.append(storage_path)

    return resolved_refs, open_paths


def _resolve_run_toolchain_set_ref(
    *,
    repo_root: Path,
    workspace_rel: str,
    run_id: str | None,
    args: argparse.Namespace,
) -> tuple[str | None, Path | None]:
    raw = str(getattr(args, "toolchain_set_ref", "") or "").strip()
    if not raw:
        return None, None

    toolchain_set_id, storage_ref = _parse_object_ref_cli(raw, flag_name="--toolchain-set-ref")
    if toolchain_set_id == "toolchain.main":
        raise _UserInputError("--toolchain-set-ref id `toolchain.main` is reserved for the built-in run toolchain input")
    resolved_storage_ref, storage_path = _resolve_run_environment_object_ref(
        repo_root=repo_root,
        workspace_rel=workspace_rel,
        run_id=run_id,
        raw=storage_ref,
        flag_name="--toolchain-set-ref",
        leaf_name=RUN_ENV_TOOLCHAIN_SET_FILENAME,
    )
    return f"{toolchain_set_id}={resolved_storage_ref}", storage_path


def _resolve_run_tolerances_ref(
    *,
    repo_root: Path,
    workspace_rel: str,
    run_id: str | None,
    args: argparse.Namespace,
) -> tuple[str | None, Path | None]:
    raw = str(getattr(args, "tolerances_ref", "") or "").strip()
    if not raw:
        return None, None

    tolerances_id, storage_ref = _parse_object_ref_cli(raw, flag_name="--tolerances-ref")
    resolved_storage_ref, storage_path = _resolve_run_environment_object_ref(
        repo_root=repo_root,
        workspace_rel=workspace_rel,
        run_id=run_id,
        raw=storage_ref,
        flag_name="--tolerances-ref",
        leaf_name=RUN_ENV_TOLERANCES_FILENAME,
    )
    return f"{tolerances_id}={resolved_storage_ref}", storage_path


def cmd_run(args: argparse.Namespace) -> int:
    from belgi.core.hash import sha256_bytes
    from belgi.core.jail import resolve_repo_rel_path, safe_relpath
    from belgi.protocol.pack import get_builtin_protocol_context

    repo_root = Path(str(args.repo)).resolve()
    tier_id: str | None = str(getattr(args, "tier", "") or "").strip() or None
    run_key: str | None = None
    attempt_id: str | None = None
    workspace_rel: str | None = None
    run_workspace_dir: Path | None = None
    run_key_dir: Path | None = None
    attempt_dir: Path | None = None
    summary_path: Path | None = None
    preimage: dict[str, object] | None = None
    chain_repo_dir: Path | None = None
    chain_out_dir: Path | None = None
    base_revision: str | None = None
    evaluated_revision: str | None = None
    revision_discovery_method: str | None = None
    upstream_ref: str | None = None
    chain_paths: list[Path] = []
    adversarial_findings_present = False
    adversarial_findings_count = 0
    findings_signal_emittable = False
    waivers_applied_count: int | None = None
    waivers_applied_refs: list[str] | None = None
    operator_anchors: OperatorAnchorInputs | None = None
    run_input_paths: list[Path] = []
    run_evidence_inputs: RunEvidenceInputs | None = None
    declared_toolchain_set_ref: str | None = None
    declared_toolchain_refs: list[str] = []
    declared_tolerances_ref: str | None = None
    run_ref: str | None = None
    intent_open_path: Path | None = None
    requested_waiver_refs: list[str] = []
    active_run_id: str | None = None
    verbose = bool(getattr(args, "verbose", False))

    def _collect_open_paths() -> list[Path]:
        candidates: list[Path] = []
        if chain_out_dir is not None:
            candidates.extend(
                [
                    chain_out_dir / "GateVerdict.Q.json",
                    chain_out_dir / "GateVerdict.R.json",
                    chain_out_dir / "GateVerdict.S.json",
                    chain_out_dir / "EvidenceManifest.json",
                ]
            )
        if intent_open_path is not None:
            candidates.append(intent_open_path)
        elif chain_repo_dir is not None:
            candidates.append(chain_repo_dir / "IntentSpec.core.md")
        if waivers_applied_refs:
            if chain_repo_dir is not None:
                candidates.extend(chain_repo_dir / Path(*ref.split("/")) for ref in waivers_applied_refs)
        elif requested_waiver_refs:
            candidates.extend(repo_root / Path(*ref.split("/")) for ref in requested_waiver_refs)
        candidates.extend(run_input_paths)
        out: list[Path] = []
        seen: set[str] = set()
        for path in candidates:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            if not path.exists():
                continue
            out.append(path)
        return out

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

        workspace_runs_dir = workspace_dir / "runs"
        store_runs_dir = _resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=False)
        migrated_keys = _migrate_legacy_run_key_dirs(
            workspace_runs_dir=workspace_runs_dir,
            store_runs_dir=store_runs_dir,
            repo_root=repo_root,
        )
        if migrated_keys:
            for migrated_key in migrated_keys:
                print(f"[belgi run] migrated legacy run_key to store: {migrated_key}", file=sys.stderr)

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
            intent_open_path = intent_path
            run_scope_run_id = _infer_run_id_from_intent_source(
                workspace_rel=workspace_rel,
                intent_source_rel=intent_source_rel,
            )
            if run_scope_run_id is not None:
                active_run_id = run_scope_run_id
                run_ref = run_scope_run_id
                run_scope_dir = _resolve_run_dir(
                    repo_root=repo_root,
                    workspace_rel=workspace_rel,
                    run_id=run_scope_run_id,
                    must_exist=True,
                )
                run_workspace_dir = run_scope_dir
                requested_waiver_refs = _load_run_waivers_applied_refs(
                    repo_root=repo_root,
                    run_dir=run_scope_dir,
                    run_id=run_scope_run_id,
                )
        else:
            intent_bytes = render_default_intent_spec(tier_id=tier_id)
            intent_source_rel = "(auto)"

        protocol = get_builtin_protocol_context()
        if tier_id == "tier-3":
            tier3_missing_reason = _tier3_missing_input_reason(args)
            if tier3_missing_reason is not None:
                raise _UserInputError(tier3_missing_reason)
        operator_anchors, run_input_paths = _resolve_shared_operator_anchors(
            repo_root=repo_root,
            args=args,
            tier_id=tier_id,
        )
        try:
            evaluated_revision = _repo_head_sha(repo_root)
        except ValueError as e:
            raise _UserInputError(f"cannot resolve evaluated revision: {e}") from e
        declared_toolchain_set_ref, toolchain_set_ref_path = _resolve_run_toolchain_set_ref(
            repo_root=repo_root,
            workspace_rel=workspace_rel,
            run_id=active_run_id,
            args=args,
        )
        if declared_toolchain_set_ref is not None and getattr(args, "toolchain_ref", None):
            raise _UserInputError("do not mix --toolchain-set-ref with shorthand --toolchain-ref values")
        if toolchain_set_ref_path is not None:
            run_input_paths.append(toolchain_set_ref_path)
        declared_toolchain_refs, toolchain_ref_paths = _resolve_run_toolchain_refs(
            repo_root=repo_root,
            args=args,
            evaluated_revision=evaluated_revision,
        )
        run_input_paths.extend(toolchain_ref_paths)
        declared_tolerances_ref, tolerances_ref_path = _resolve_run_tolerances_ref(
            repo_root=repo_root,
            workspace_rel=workspace_rel,
            run_id=active_run_id,
            args=args,
        )
        if tolerances_ref_path is not None:
            run_input_paths.append(tolerances_ref_path)
        run_evidence_inputs, run_evidence_paths = _resolve_run_evidence_inputs(
            repo_root=repo_root,
            args=args,
            tier_id=tier_id,
        )
        run_input_paths.extend(run_evidence_paths)
        base_revision, revision_discovery_method, upstream_ref = _discover_base_revision(
            repo_root=repo_root,
            explicit_base_revision=getattr(args, "base_revision", None),
        )
        preimage = _derive_run_key_preimage(
            repo_root=repo_root,
            tier_id=tier_id,
            workspace_rel=workspace_rel,
            intent_source_rel=intent_source_rel,
            intent_spec_sha256=sha256_bytes(intent_bytes),
            base_revision=base_revision,
            evaluated_revision=evaluated_revision,
            protocol_pack_name=protocol.pack_name,
            protocol_pack_id=protocol.pack_id,
            protocol_manifest_sha256=protocol.manifest_sha256,
            declared_toolchain_set_ref=declared_toolchain_set_ref,
            declared_toolchain_refs=declared_toolchain_refs if declared_toolchain_refs else None,
            declared_tolerances_ref=declared_tolerances_ref,
        )
        run_key = _compute_run_key_from_preimage(preimage)

        run_key_dir = store_runs_dir / run_key
        if run_key_dir.exists() and (run_key_dir.is_symlink() or not run_key_dir.is_dir()):
            raise ValueError(f"invalid run_key directory: {run_key_dir}")
        run_key_dir.mkdir(parents=True, exist_ok=True)

        attempt_id = _next_attempt_id(run_key_dir)
        attempt_dir = run_key_dir / attempt_id
        if attempt_dir.exists():
            raise ValueError(f"attempt directory already exists: {attempt_dir}")
        attempt_dir.mkdir(parents=False, exist_ok=False)
        summary_path = attempt_dir / RUN_SUMMARY_FILENAME
        chain_repo_dir = attempt_dir / CHAIN_REPO_DIRNAME
        chain_out_dir = chain_repo_dir / CHAIN_OUT_DIRNAME

        with contextlib.redirect_stdout(sys.stderr):
            chain_result = orchestrate_chain_run(
                source_repo_root=repo_root,
                chain_repo_dir=chain_repo_dir,
                run_key=run_key,
                tier_id=tier_id,
                base_revision=base_revision,
                evaluated_revision=evaluated_revision,
                revision_discovery_method=revision_discovery_method,
                upstream_ref=upstream_ref,
                intent_bytes=intent_bytes,
                protocol=protocol,
                applied_waiver_refs=requested_waiver_refs if requested_waiver_refs else None,
                operator_anchors=operator_anchors,
                run_evidence=run_evidence_inputs,
                declared_toolchain_set_ref=declared_toolchain_set_ref,
                declared_toolchain_refs=declared_toolchain_refs if declared_toolchain_refs else None,
                declared_tolerances_ref=declared_tolerances_ref,
                workspace_rel=workspace_rel,
                current_run_id=active_run_id,
            )
        chain_repo_dir = chain_result.chain_repo_dir
        chain_out_dir = chain_result.chain_out_dir
        chain_paths = chain_result.chain_paths
        adversarial_findings_present = chain_result.adversarial_findings_present
        adversarial_findings_count = chain_result.adversarial_findings_count
        policy_adv_path = chain_out_dir / "artifacts" / "policy.adversarial_scan.json"
        if policy_adv_path.is_file():
            policy_findings_present, policy_finding_count = _load_adversarial_signal_from_policy_report(
                policy_adv_path
            )
            findings_signal_emittable = True
            raw_findings_present = adversarial_findings_present
            raw_finding_count = adversarial_findings_count
            adversarial_findings_present = policy_findings_present
            adversarial_findings_count = policy_finding_count
            valid_runtime_count = (
                isinstance(raw_finding_count, int)
                and not isinstance(raw_finding_count, bool)
                and raw_finding_count >= 0
            )
            if not isinstance(raw_findings_present, bool) or not valid_runtime_count:
                raise ValueError("adversarial findings signal missing/invalid from orchestration output")
            if raw_findings_present != policy_findings_present or raw_finding_count != policy_finding_count:
                raise ValueError("adversarial findings signal mismatch with policy.adversarial_scan")
        waivers_applied_refs = list(chain_result.applied_waiver_refs)
        waivers_applied_count = len(waivers_applied_refs)
        _validate_paths_within_attempt(attempt_dir=attempt_dir, paths=chain_paths)
        wrote_summary = _write_run_summary_if_ready(
            repo_root=repo_root,
            summary_path=summary_path,
            run_key=run_key,
            attempt_id=attempt_id,
            tier_id=tier_id,
            workspace_rel=workspace_rel,
            run_key_dir=run_key_dir,
            attempt_dir=attempt_dir,
            run_key_preimage=preimage,
            chain_repo_dir=chain_repo_dir,
            chain_out_dir=chain_out_dir,
            chain_paths=chain_paths,
            adversarial_findings_present=adversarial_findings_present,
            adversarial_findings_count=adversarial_findings_count,
            waivers_applied_count=waivers_applied_count or 0,
            waivers_applied_refs=waivers_applied_refs or [],
            verdict="GO",
            primary_reason="",
        )
        if not wrote_summary:
            raise ValueError("internal error: failed to finalize run summary for attempt")
        _write_run_workspace_pointers(
            repo_root=repo_root,
            run_workspace_dir=run_workspace_dir,
            run_key=run_key,
            attempt_id=attempt_id,
            chain_out_dir=chain_out_dir,
        )

    except _UserInputError as e:
        reason = str(e)
        try:
            _write_run_summary_if_ready(
                repo_root=repo_root,
                summary_path=summary_path,
                run_key=run_key,
                attempt_id=attempt_id,
                tier_id=tier_id,
                workspace_rel=workspace_rel,
                run_key_dir=run_key_dir,
                attempt_dir=attempt_dir,
                run_key_preimage=preimage,
                chain_repo_dir=chain_repo_dir,
                chain_out_dir=chain_out_dir,
                chain_paths=chain_paths,
                adversarial_findings_present=adversarial_findings_present,
                adversarial_findings_count=adversarial_findings_count,
                waivers_applied_count=waivers_applied_count or 0,
                waivers_applied_refs=waivers_applied_refs or [],
                verdict="NO-GO",
                primary_reason=reason,
            )
        except Exception as summary_err:
            reason = f"{reason}; summary_finalize_error={summary_err}"
        cli_render._emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=reason,
            tier_id=tier_id,
            run_key=run_key,
            attempt_id=attempt_id,
            findings_present=adversarial_findings_present if findings_signal_emittable else None,
            finding_count=adversarial_findings_count if findings_signal_emittable else None,
        )
        next_instruction = "Do fix input arguments or repository state, then re-run `belgi run --help`."
        _write_run_workspace_pointers(
            repo_root=repo_root,
            run_workspace_dir=run_workspace_dir,
            run_key=run_key,
            attempt_id=attempt_id,
            chain_out_dir=chain_out_dir,
        )
        _emit_run_failure_links(
            repo_root=repo_root,
            level="USER_ERROR",
            tier_id=tier_id,
            run_ref=run_ref,
            run_key=run_key,
            attempt_id=attempt_id,
            primary_reason=reason,
            remediation_next_instruction=next_instruction,
            chain_out_dir=chain_out_dir,
            gate_verdict_path=_primary_gate_verdict_path(chain_out_dir, primary_reason=reason),
            evidence_manifest_path=_evidence_manifest_path(chain_out_dir),
            run_workspace_dir=run_workspace_dir,
            open_paths=_collect_open_paths(),
            verbose=verbose,
        )
        return RC_USER_ERROR
    except ValueError as e:
        reason = str(e)
        try:
            _write_run_summary_if_ready(
                repo_root=repo_root,
                summary_path=summary_path,
                run_key=run_key,
                attempt_id=attempt_id,
                tier_id=tier_id,
                workspace_rel=workspace_rel,
                run_key_dir=run_key_dir,
                attempt_dir=attempt_dir,
                run_key_preimage=preimage,
                chain_repo_dir=chain_repo_dir,
                chain_out_dir=chain_out_dir,
                chain_paths=chain_paths,
                adversarial_findings_present=adversarial_findings_present,
                adversarial_findings_count=adversarial_findings_count,
                waivers_applied_count=waivers_applied_count or 0,
                waivers_applied_refs=waivers_applied_refs or [],
                verdict="NO-GO",
                primary_reason=reason,
            )
        except Exception as summary_err:
            reason = f"{reason}; summary_finalize_error={summary_err}"
        cli_render._emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=reason,
            tier_id=tier_id,
            run_key=run_key,
            attempt_id=attempt_id,
            findings_present=adversarial_findings_present if findings_signal_emittable else None,
            finding_count=adversarial_findings_count if findings_signal_emittable else None,
        )
        next_instruction = _run_no_go_next_instruction(chain_out_dir=chain_out_dir, primary_reason=reason)
        _write_run_workspace_pointers(
            repo_root=repo_root,
            run_workspace_dir=run_workspace_dir,
            run_key=run_key,
            attempt_id=attempt_id,
            chain_out_dir=chain_out_dir,
        )
        _emit_run_failure_links(
            repo_root=repo_root,
            level="NO-GO",
            tier_id=tier_id,
            run_ref=run_ref,
            run_key=run_key,
            attempt_id=attempt_id,
            primary_reason=reason,
            remediation_next_instruction=next_instruction,
            chain_out_dir=chain_out_dir,
            gate_verdict_path=_primary_gate_verdict_path(chain_out_dir, primary_reason=reason),
            evidence_manifest_path=_evidence_manifest_path(chain_out_dir),
            run_workspace_dir=run_workspace_dir,
            open_paths=_collect_open_paths(),
            verbose=verbose,
        )
        return RC_NO_GO
    except Exception as e:
        reason = str(e)
        try:
            _write_run_summary_if_ready(
                repo_root=repo_root,
                summary_path=summary_path,
                run_key=run_key,
                attempt_id=attempt_id,
                tier_id=tier_id,
                workspace_rel=workspace_rel,
                run_key_dir=run_key_dir,
                attempt_dir=attempt_dir,
                run_key_preimage=preimage,
                chain_repo_dir=chain_repo_dir,
                chain_out_dir=chain_out_dir,
                chain_paths=chain_paths,
                adversarial_findings_present=adversarial_findings_present,
                adversarial_findings_count=adversarial_findings_count,
                waivers_applied_count=waivers_applied_count or 0,
                waivers_applied_refs=waivers_applied_refs or [],
                verdict="NO-GO",
                primary_reason=reason,
            )
        except Exception as summary_err:
            reason = f"{reason}; summary_finalize_error={summary_err}"
        _write_run_workspace_pointers(
            repo_root=repo_root,
            run_workspace_dir=run_workspace_dir,
            run_key=run_key,
            attempt_id=attempt_id,
            chain_out_dir=chain_out_dir,
        )
        cli_render._emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=reason,
            tier_id=tier_id,
            run_key=run_key,
            attempt_id=attempt_id,
            findings_present=adversarial_findings_present if findings_signal_emittable else None,
            finding_count=adversarial_findings_count if findings_signal_emittable else None,
        )
        _emit_run_failure_links(
            repo_root=repo_root,
            level="INTERNAL_ERROR",
            tier_id=tier_id,
            run_ref=run_ref,
            run_key=run_key,
            attempt_id=attempt_id,
            primary_reason=reason,
            remediation_next_instruction=(
                "Do inspect generated artifacts and logs, then fix the internal error before re-run."
            ),
            chain_out_dir=chain_out_dir,
            gate_verdict_path=_primary_gate_verdict_path(chain_out_dir, primary_reason=reason),
            evidence_manifest_path=_evidence_manifest_path(chain_out_dir),
            run_workspace_dir=run_workspace_dir,
            open_paths=_collect_open_paths(),
            verbose=verbose,
        )
        return RC_INTERNAL_ERROR

    cli_render._emit_machine_result(
        ok=True,
        verdict="GO",
        primary_reason="",
        tier_id=tier_id,
        run_key=run_key,
        attempt_id=attempt_id,
        waivers_applied_count=waivers_applied_count,
        waivers_applied_refs=waivers_applied_refs,
        findings_present=adversarial_findings_present if findings_signal_emittable else None,
        finding_count=adversarial_findings_count if findings_signal_emittable else None,
    )
    _emit_run_success_links(
        repo_root=repo_root,
        tier_id=tier_id,
        run_ref=run_ref,
        run_key=run_key,
        attempt_id=attempt_id,
        run_workspace_dir=run_workspace_dir,
        chain_out_dir=chain_out_dir,
        chain_repo_dir=chain_repo_dir,
        intent_open_path=intent_open_path,
        verbose=verbose,
    )
    return RC_GO
