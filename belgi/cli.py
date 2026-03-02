#!/usr/bin/env python3
"""BELGI CLI — Protocol pack management and evidence generation tools.

This is the installable CLI entrypoint (console_scripts).

Subcommands:
- belgi init           → Initialize adopter overlay defaults in a repo
- belgi policy stub    → Generate deterministic PolicyReportPayload stubs
- belgi run new        → Create deterministic adopter run workspace
- belgi run --tier     → Create deterministic run attempt under run_key/attempt_id
- belgi waiver new     → Create schema-valid waiver draft in run inputs
- belgi waiver apply   → Record run-local applied waiver refs for C1
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
import importlib
import json
import os
import re
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, metadata, version
from importlib.resources import as_file, files
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

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
RUN_KEY_DIR_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_RUN_TIERS = {"tier-0", "tier-1"}
RUN_INPUTS_DIRNAME = "inputs"
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


class _CliUsageError(Exception):
    """Argparse/usage-level error (mapped to RC_USER_ERROR)."""

    def __init__(self, message: str, parser: argparse.ArgumentParser | None) -> None:
        super().__init__(message)
        self.message = str(message or "").strip()
        self.parser = parser


class _BelgiArgumentParser(argparse.ArgumentParser):
    """ArgumentParser variant that raises deterministic usage errors."""

    def error(self, message: str) -> NoReturn:
        raise _CliUsageError(message, self)


def _emit_machine_result(
    *,
    ok: bool,
    verdict: str,
    primary_reason: str,
    tier_id: str | None,
    run_key: str | None,
    attempt_id: str | None,
    waivers_applied_count: int | None = None,
    waivers_applied_refs: list[str] | None = None,
    findings_present: bool | None = None,
    finding_count: int | None = None,
) -> None:
    payload = {
        "ok": bool(ok),
        "verdict": verdict,
        "primary_reason": str(primary_reason),
        "tier_id": tier_id,
        "run_key": run_key,
        "attempt_id": attempt_id,
    }
    if waivers_applied_count is not None:
        payload["waivers_applied_count"] = int(waivers_applied_count)
    if waivers_applied_refs is not None:
        payload["waivers_applied_refs"] = list(waivers_applied_refs)
    if findings_present is not None:
        payload["findings_present"] = bool(findings_present)
    if finding_count is not None:
        payload["finding_count"] = int(finding_count)
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def _stderr_supports_color() -> bool:
    if os.environ.get("NO_COLOR") is not None or os.environ.get("BELGI_NO_COLOR") is not None:
        return False
    isatty = getattr(sys.stderr, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except Exception:
        return False


def _colorize_status_token(token: str, *, enabled: bool) -> str:
    if not enabled:
        return token
    color = _ANSI_STATUS_COLORS.get(token)
    if not color:
        return token
    return f"{color}{token}{_ANSI_RESET}"


def _emit_human_status(*, prefix: str, level: str, lines: list[str]) -> None:
    normalized_lines = ["" if line is None else str(line) for line in lines]
    if not normalized_lines:
        normalized_lines = [""]
    status_token = str(level or "INFO").upper()
    colored_token = _colorize_status_token(status_token, enabled=_stderr_supports_color())
    first_line = normalized_lines[0]
    if first_line:
        print(f"{prefix} {colored_token}: {first_line}", file=sys.stderr)
    else:
        print(f"{prefix} {colored_token}", file=sys.stderr)
    for extra in normalized_lines[1:]:
        if extra == "":
            print("", file=sys.stderr)
            continue
        print(f"{prefix} {extra}", file=sys.stderr)


def _emit_cli_user_error_result(
    *,
    primary_reason: str,
    parser: argparse.ArgumentParser | None = None,
    help_to_stderr: bool = False,
) -> int:
    _emit_machine_result(
        ok=False,
        verdict="NO-GO",
        primary_reason=primary_reason,
        tier_id=None,
        run_key=None,
        attempt_id=None,
    )
    if parser is not None:
        usage = parser.format_usage()
        if usage:
            print(usage, file=sys.stderr, end="")
        if help_to_stderr:
            print(parser.format_help(), file=sys.stderr, end="")
        prog = str(getattr(parser, "prog", "belgi") or "belgi")
    else:
        prog = "belgi"
    _emit_human_status(prefix=prog, level="USER_ERROR", lines=[primary_reason])
    return RC_USER_ERROR


def _normalize_cli_exit_code(raw_rc: int) -> int:
    """Map legacy subcommand return codes onto the public BELGI CLI RC model."""
    if raw_rc == RC_GO:
        return RC_GO
    if raw_rc == RC_NO_GO:
        return RC_NO_GO
    if raw_rc == RC_USER_ERROR:
        return RC_USER_ERROR
    if raw_rc == RC_INTERNAL_ERROR:
        return RC_INTERNAL_ERROR
    if raw_rc in (1, 2):
        return RC_NO_GO
    if raw_rc == 3:
        return RC_USER_ERROR
    return RC_INTERNAL_ERROR


@contextlib.contextmanager
def _patched_argv(prog: str, argv: list[str]) -> Any:
    original_argv = list(sys.argv)
    try:
        sys.argv = [prog, *argv]
        yield
    finally:
        sys.argv = original_argv


def _invoke_module_main(module_name: str, argv: list[str]) -> int:
    module = importlib.import_module(module_name)
    main_fn = getattr(module, "main", None)
    if not callable(main_fn):
        raise RuntimeError(f"{module_name} does not expose callable main()")

    try:
        with _patched_argv(module_name, argv):
            rc = main_fn()
    except SystemExit as e:
        if isinstance(e.code, int):
            return int(e.code)
        return 3

    if not isinstance(rc, int):
        raise RuntimeError(f"{module_name}.main() returned non-int exit code: {type(rc).__name__}")
    return int(rc)


def _run_stage_forwarder(
    *,
    stage_name: str,
    parser: argparse.ArgumentParser,
    module_name: str,
    forward_args: list[str],
) -> int:
    if not forward_args:
        return _emit_cli_user_error_result(
            primary_reason=f"missing stage arguments; see `belgi stage {stage_name} --help`",
            parser=parser,
        )

    try:
        raw_rc = _invoke_module_main(module_name, forward_args)
    except ModuleNotFoundError as e:
        missing_name = str(getattr(e, "name", "") or "").strip()
        message = str(e)
        if (
            missing_name == "chain"
            or missing_name.startswith("chain.")
            or "No module named 'chain'" in message
            or "No module named \"chain\"" in message
        ):
            return _emit_cli_user_error_result(
                primary_reason=(
                    "repo-local stage module missing; run inside BELGI source checkout or "
                    "use canonical python -m chain.<...> invocation"
                ),
                parser=parser,
            )
        print(f"[belgi stage {stage_name}] ERROR: {e}", file=sys.stderr)
        print(f"[belgi stage {stage_name}] Remediation: run `belgi stage {stage_name} --help`.", file=sys.stderr)
        return RC_INTERNAL_ERROR
    except Exception as e:
        print(f"[belgi stage {stage_name}] ERROR: {e}", file=sys.stderr)
        print(f"[belgi stage {stage_name}] Remediation: run `belgi stage {stage_name} --help`.", file=sys.stderr)
        return RC_INTERNAL_ERROR

    normalized_rc: int
    if raw_rc == RC_GO:
        normalized_rc = RC_GO
    elif raw_rc == RC_NO_GO:
        normalized_rc = RC_NO_GO
    elif raw_rc == RC_USER_ERROR:
        normalized_rc = RC_USER_ERROR
    elif raw_rc == RC_INTERNAL_ERROR:
        normalized_rc = RC_INTERNAL_ERROR
    elif raw_rc == 2:
        normalized_rc = RC_NO_GO
    elif raw_rc == 3:
        normalized_rc = RC_USER_ERROR
    else:
        normalized_rc = RC_INTERNAL_ERROR

    if raw_rc in (2, 3):
        print(f"[belgi stage {stage_name}] Remediation: run `belgi stage {stage_name} --help`.", file=sys.stderr)
    return normalized_rc


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
    base_revision: str,
    evaluated_revision: str,
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
        "belgi verify --repo .\n"
        "```\n\n"
        "## Layout map\n"
        f"- `{run_root}/<run_id>/` = human workspace + pointers.\n"
        f"- `{store_root}/<run_key>/<attempt_id>/` = authoritative artifacts.\n"
        "- `open_verdict.txt` and `open_evidence.txt` point to the latest verdict/evidence paths.\n\n"
        "## On NO-GO\n"
        "- Check `gate_verdict_path` first.\n"
        "- Check `evidence_manifest_path` for indexed artifacts and command records.\n"
        "- `remediation.next_instruction` is the authoritative next step.\n\n"
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
    return (
        "# RUN\n\n"
        f"Run ID: `{run_id}`\n\n"
        "Minimal operator loop:\n\n"
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
        "4. Run BELGI:\n\n"
        "```bash\n"
        f"belgi run --repo . --tier tier-1 --intent-spec .belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md --base-revision \"${{BASE_SHA40}}\"\n"
        "```\n\n"
        "5. Verify and triage:\n\n"
        "```bash\n"
        "belgi verify --repo .\n"
        "```\n\n"
        "Artifacts are created under `.belgi/store/runs/<run_key>/<attempt_id>/`.\n"
    )


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
        err_path = str(first.get("path") or label)
        msg = str(first.get("message") or "schema validation failed")
        raise ValueError(f"{label} invalid: {err_path}: {msg}")
    return waiver_obj


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
    inputs_dir = run_dir / RUN_INPUTS_DIRNAME
    intent_path = _run_intent_path(run_dir)
    waivers_dir = _run_waivers_dir(run_dir)
    runbook_template_path = run_dir / "RUN.md"
    run_key_pointer_path = _run_pointer_run_key_path(run_dir)
    last_attempt_pointer_path = _run_pointer_last_attempt_path(run_dir)
    open_verdict_pointer_path = _run_pointer_open_verdict_path(run_dir)
    open_evidence_pointer_path = _run_pointer_open_evidence_path(run_dir)
    placeholders = [
        run_dir / "tolerances.json",
        run_dir / "toolchain.json",
    ]

    created: list[Path] = []
    updated: list[Path] = []

    if inputs_dir.exists():
        if inputs_dir.is_symlink() or not inputs_dir.is_dir():
            raise ValueError(f"invalid path in run workspace: {inputs_dir}")
    else:
        inputs_dir.mkdir(parents=True, exist_ok=True)
        created.append(inputs_dir)

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

    for path in placeholders:
        state = _write_json_placeholder(path, force=force)
        if state == "created":
            created.append(path)
        elif state == "updated":
            updated.append(path)

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
        runbook_template_path,
        *placeholders,
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
        workspace_rel, workspace_dir = _resolve_workspace_dir(
            repo_root,
            getattr(args, "workspace", DEFAULT_WORKSPACE_REL),
            must_exist=True,
        )
        _migrate_legacy_run_key_dirs(
            workspace_runs_dir=workspace_dir / "runs",
            store_runs_dir=_resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=False),
            repo_root=repo_root,
        )
        run_id = _validate_run_id(str(args.run_id))
        gate_id = str(getattr(args, "gate", "") or "").strip().upper()
        if gate_id not in ("Q", "R"):
            raise ValueError("--gate must be Q or R")
        rule_id = str(getattr(args, "rule_id", "") or "").strip()
        if not rule_id:
            raise ValueError("--rule-id missing/invalid")
        waiver_id = _validate_waiver_id(str(args.waiver_id))
        expires_at = str(getattr(args, "expires_at", "") or "").strip()
        if not _RFC3339_UTC_RE.fullmatch(expires_at):
            raise ValueError("--expires-at must be RFC3339 (e.g. 2100-01-01T00:00:00Z)")
        run_dir = _resolve_run_dir(repo_root=repo_root, workspace_rel=workspace_rel, run_id=run_id, must_exist=True)

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
            waiver_path = _run_waivers_dir(run_dir) / f"{waiver_id}.json"

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
            "status": "active",
        }
        _assert_valid_waiver_doc(waiver_obj=waiver_obj, label="waiver")
        _write_json(waiver_path, waiver_obj)
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
        workspace_rel, workspace_dir = _resolve_workspace_dir(
            repo_root,
            getattr(args, "workspace", DEFAULT_WORKSPACE_REL),
            must_exist=True,
        )
        _migrate_legacy_run_key_dirs(
            workspace_runs_dir=workspace_dir / "runs",
            store_runs_dir=_resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=False),
            repo_root=repo_root,
        )
        run_id = _validate_run_id(str(args.run_id))
        run_dir = _resolve_run_dir(repo_root=repo_root, workspace_rel=workspace_rel, run_id=run_id, must_exist=True)
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
        applied_path = _run_waivers_applied_path(run_dir)
        existed = applied_path.exists()
        refs = _load_run_waivers_applied_refs(repo_root=repo_root, run_dir=run_dir, run_id=run_id)
        if waiver_rel not in refs:
            refs.append(waiver_rel)
        _write_json(applied_path, _render_run_waivers_applied_doc(run_id=run_id, waivers=refs))
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
        f"[belgi waiver apply] next: belgi run --repo . --tier tier-1 --intent-spec {safe_relpath(repo_root, _run_intent_path(run_dir))} --base-revision <SHA40>",
        file=sys.stderr,
    )
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


def _evidence_manifest_path(chain_out_dir: Path | None) -> Path | None:
    if chain_out_dir is None:
        return None
    return chain_out_dir / "EvidenceManifest.json"


def _env_truthy(name: str) -> bool:
    raw = str(os.environ.get(name, "") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _hyperlinks_enabled() -> bool:
    return _env_truthy("BELGI_HYPERLINKS") and _stderr_supports_color()


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
    run_tokens = [f"verdict=NO-GO", f"tier={tier_id or 'UNKNOWN'}"]
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
        next_instruction = "Do inspect the reported reason, fix inputs, then rerun `belgi run`."
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

    _emit_human_status(prefix="[belgi run]", level=level, lines=lines)


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
    run_tokens = [f"verdict=GO", f"tier={tier_id or 'UNKNOWN'}"]
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

    _emit_human_status(prefix="[belgi run]", level="GO", lines=lines)


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
    run_ref: str | None = None
    intent_open_path: Path | None = None
    requested_waiver_refs: list[str] = []
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
        try:
            evaluated_revision = _repo_head_sha(repo_root)
        except ValueError as e:
            raise _UserInputError(f"cannot resolve evaluated revision: {e}") from e
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
        _emit_machine_result(
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
        _emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=reason,
            tier_id=tier_id,
            run_key=run_key,
            attempt_id=attempt_id,
            findings_present=adversarial_findings_present if findings_signal_emittable else None,
            finding_count=adversarial_findings_count if findings_signal_emittable else None,
        )
        next_instruction = ""
        if chain_out_dir is not None:
            for gate_name in _preferred_gate_verdict_order(reason):
                next_instruction = _load_next_instruction_from_gate_verdict(chain_out_dir / gate_name) or ""
                if next_instruction:
                    break
            if not next_instruction:
                next_instruction = _load_next_instruction_from_c1_parse_diagnostic(chain_out_dir) or ""
        if not next_instruction:
            next_instruction = "Do inspect the reported reason, fix inputs, then rerun `belgi run`."
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
        _emit_machine_result(
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

    _emit_machine_result(
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


def _validate_run_key_arg(raw: str) -> str:
    run_key = str(raw or "").strip().lower()
    if not run_key:
        raise _UserInputError("--run-key missing/invalid")
    if RUN_KEY_DIR_PATTERN.fullmatch(run_key) is None:
        raise _UserInputError("--run-key must be 64 lowercase hex")
    return run_key


def _validate_attempt_id_arg(raw: str) -> str:
    attempt_id = str(raw or "").strip()
    if not attempt_id:
        raise _UserInputError("--attempt-id missing/invalid")
    if ATTEMPT_ID_PATTERN.fullmatch(attempt_id) is None:
        raise _UserInputError("--attempt-id must match attempt-0001 format")
    return attempt_id


def _max_attempt_id_in_run_key_dir(run_key_dir: Path) -> str:
    if run_key_dir.is_symlink() or not run_key_dir.is_dir():
        raise _UserInputError(f"invalid run_key directory: {run_key_dir}")
    best: int | None = None
    for child in _list_dirs_sorted(run_key_dir):
        m = ATTEMPT_ID_PATTERN.fullmatch(child.name)
        if m is None:
            raise _UserInputError(f"unexpected attempt directory name: {child.name}")
        idx = int(m.group(1))
        best = idx if best is None or idx > best else best
    if best is None:
        raise _UserInputError(f"run_key has no attempts: {run_key_dir.name}")
    return f"attempt-{best:04d}"


def _read_pointer_text(path: Path, *, label: str) -> str:
    if not path.exists():
        raise _UserInputError(f"{label} missing: {path}")
    if path.is_symlink() or not path.is_file():
        raise _UserInputError(f"{label} invalid path type: {path}")
    value = path.read_text(encoding="utf-8", errors="strict").strip()
    if not value:
        raise _UserInputError(f"{label} empty: {path}")
    return value


def _select_verify_attempt_dir(
    *,
    repo_root: Path,
    workspace_dir: Path,
    store_runs_dir: Path,
    input_target: Path | None,
    run_key_arg: str | None,
    attempt_id_arg: str | None,
) -> tuple[Path, str, str | None]:
    if input_target is not None:
        attempt_dirs = _discover_attempt_dirs(input_target)
        if len(attempt_dirs) != 1:
            raise _UserInputError(
                "--in must resolve to exactly one attempt directory; "
                "use --run-key/--attempt-id for explicit selection"
            )
        return attempt_dirs[0], "explicit", None

    if attempt_id_arg and not run_key_arg:
        raise _UserInputError("--attempt-id requires --run-key")

    if run_key_arg:
        run_key = _validate_run_key_arg(run_key_arg)
        run_key_dir = store_runs_dir / run_key
        if not run_key_dir.exists() or run_key_dir.is_symlink() or not run_key_dir.is_dir():
            raise _UserInputError(f"run_key missing: {run_key}")
        if attempt_id_arg:
            attempt_id = _validate_attempt_id_arg(attempt_id_arg)
        else:
            attempt_id = _max_attempt_id_in_run_key_dir(run_key_dir)
        attempt_dir = run_key_dir / attempt_id
        if not attempt_dir.exists() or attempt_dir.is_symlink() or not attempt_dir.is_dir():
            raise _UserInputError(f"attempt missing for run_key {run_key}: {attempt_id}")
        return attempt_dir, "explicit", None

    runs_dir = workspace_dir / "runs"
    if runs_dir.exists():
        candidates: list[tuple[str, Path]] = []
        for run_dir in _list_dirs_sorted(runs_dir):
            run_id = run_dir.name
            last_attempt_path = _run_pointer_last_attempt_path(run_dir)
            if not last_attempt_path.exists():
                continue
            attempt_id = _validate_attempt_id_arg(_read_pointer_text(last_attempt_path, label=f"{run_id} last_attempt"))
            run_key = _validate_run_key_arg(_read_pointer_text(_run_pointer_run_key_path(run_dir), label=f"{run_id} run_key"))
            attempt_dir = store_runs_dir / run_key / attempt_id
            if not attempt_dir.exists() or attempt_dir.is_symlink() or not attempt_dir.is_dir():
                raise _UserInputError(
                    f"pointer target missing for run {run_id}: .belgi/store/runs/{run_key}/{attempt_id}"
                )
            candidates.append((run_id, attempt_dir))
        if candidates:
            candidates.sort(key=lambda item: item[0])
            run_id, attempt_dir = candidates[-1]
            return attempt_dir, "pointer", run_id

    run_key_dirs = _list_dirs_sorted(store_runs_dir)
    run_key_candidates: list[Path] = []
    for run_key_dir in run_key_dirs:
        if RUN_KEY_DIR_PATTERN.fullmatch(run_key_dir.name.lower()) is None:
            raise _UserInputError(f"unexpected store run_key directory name: {run_key_dir.name}")
        run_key_candidates.append(run_key_dir)
    if not run_key_candidates:
        raise _UserInputError("no run attempts found under .belgi/store/runs")
    run_key_candidates.sort(key=lambda p: p.name)
    latest_run_key_dir = run_key_candidates[-1]
    latest_attempt_id = _max_attempt_id_in_run_key_dir(latest_run_key_dir)
    return latest_run_key_dir / latest_attempt_id, "latest", None


def _resolve_run_workspace_for_attempt(
    *,
    workspace_dir: Path,
    run_key: str,
    attempt_id: str,
) -> tuple[str | None, Path | None]:
    runs_dir = workspace_dir / "runs"
    if not runs_dir.exists():
        return None, None
    matches: list[tuple[str, Path]] = []
    for run_dir in _list_dirs_sorted(runs_dir):
        run_id = run_dir.name
        run_key_path = _run_pointer_run_key_path(run_dir)
        last_attempt_path = _run_pointer_last_attempt_path(run_dir)
        if not run_key_path.exists() or not last_attempt_path.exists():
            continue
        try:
            pointer_run_key = _validate_run_key_arg(_read_pointer_text(run_key_path, label=f"{run_id} run_key"))
            pointer_attempt = _validate_attempt_id_arg(
                _read_pointer_text(last_attempt_path, label=f"{run_id} last_attempt")
            )
        except _UserInputError:
            continue
        if pointer_run_key == run_key and pointer_attempt == attempt_id:
            matches.append((run_id, run_dir))
    if not matches:
        return None, None
    matches.sort(key=lambda item: item[0])
    return matches[-1]


def _verify_next_instruction(*, chain_out_dir: Path | None, primary_reason: str) -> str:
    for gate_name in _preferred_gate_verdict_order(primary_reason):
        gate_path = chain_out_dir / gate_name if chain_out_dir is not None else None
        if gate_path is not None:
            next_instruction = _load_next_instruction_from_gate_verdict(gate_path)
            if next_instruction:
                return next_instruction
    parse_next = _load_next_instruction_from_c1_parse_diagnostic(chain_out_dir)
    if parse_next:
        return parse_next
    return "Do inspect the reported reason, fix artifacts/inputs, then rerun `belgi verify`."


def _emit_verify_result_block(
    *,
    repo_root: Path,
    verdict: str,
    selected_by: str,
    run_ref: str | None,
    run_key: str | None,
    attempt_id: str | None,
    primary_reason: str,
    next_instruction: str,
    attempt_dir: Path | None,
    run_workspace_dir: Path | None,
    verbose: bool,
) -> None:
    from belgi.core.jail import safe_relpath

    family = _platform_family()
    show_all_open = _show_all_open_helpers(verbose=verbose)
    chain_out_dir = attempt_dir / "repo" / "out" if attempt_dir is not None else None
    if chain_out_dir is not None and (
        not chain_out_dir.exists() or chain_out_dir.is_symlink() or not chain_out_dir.is_dir()
    ):
        chain_out_dir = None

    gate_verdict_path = _primary_gate_verdict_path(chain_out_dir, primary_reason=primary_reason)
    primary_gate = _gate_letter_from_verdict_path(gate_verdict_path) or "R"
    gate_paths = _gate_verdict_paths(chain_out_dir)
    gate_status_raw = _gate_status_map(gate_paths)
    gate_status = {
        gate: (gate_status_raw[gate] if gate_status_raw[gate] in {"GO", "NO-GO"} else "missing")
        for gate in ("Q", "R", "S")
    }

    manifest_path = _evidence_manifest_path(chain_out_dir)
    manifest_present = (
        manifest_path is not None
        and manifest_path.exists()
        and not manifest_path.is_symlink()
        and manifest_path.is_file()
    )
    seal_path: Path | None = None
    if verdict == "GO" and chain_out_dir is not None:
        maybe_seal = chain_out_dir / "SealManifest.json"
        if maybe_seal.exists() and not maybe_seal.is_symlink() and maybe_seal.is_file():
            seal_path = maybe_seal

    verdict_ptr, _ = _run_workspace_pointer_targets(run_workspace_dir)
    verdict_display_path = verdict_ptr if (verdict_ptr is not None and not verbose) else gate_verdict_path

    intent_target: Path | None = None
    waivers_target: Path | None = None
    if run_workspace_dir is not None:
        maybe_intent = _run_intent_path(run_workspace_dir)
        if maybe_intent.exists() and not maybe_intent.is_symlink() and maybe_intent.is_file():
            intent_target = maybe_intent
        maybe_waivers = _run_waivers_dir(run_workspace_dir)
        if maybe_waivers.exists() and not maybe_waivers.is_symlink() and maybe_waivers.is_dir():
            waivers_target = maybe_waivers
    if attempt_dir is not None:
        maybe_repo_intent = attempt_dir / "repo" / "IntentSpec.core.md"
        if intent_target is None and maybe_repo_intent.exists() and not maybe_repo_intent.is_symlink() and maybe_repo_intent.is_file():
            intent_target = maybe_repo_intent
        maybe_applied = attempt_dir / "repo" / "out" / "inputs" / "waivers_applied"
        if waivers_target is None and maybe_applied.exists() and not maybe_applied.is_symlink() and maybe_applied.is_file():
            waivers_target = maybe_applied

    summary_tokens = [
        f"verdict={verdict}",
        f"verified_key={_short_run_key(run_key) or 'UNKNOWN'}",
        f"verified_attempt={_short_attempt_id(attempt_id) or 'UNKNOWN'}",
        f"selected_by={selected_by}",
    ]
    lines = [
        "summary: " + " ".join(summary_tokens),
        "",
        f"cause: {primary_reason}",
        f"next: {next_instruction}",
        "",
        "evidence:",
        f"  gate: {primary_gate}",
        f"  gate_status: Q={gate_status['Q']} R={gate_status['R']} S={gate_status['S']}",
    ]

    verdict_label = f"verdict_{primary_gate}"
    if verdict_display_path is not None:
        lines.append(f"  {verdict_label}: {safe_relpath(repo_root, verdict_display_path)}")
    else:
        lines.append(f"  {verdict_label}: missing")
    lines.append(f"  manifest: {'present' if manifest_present else 'missing'}")
    if seal_path is not None:
        lines.append(f"  seal: {safe_relpath(repo_root, seal_path)}")

    lines.append("")
    lines.append("open:")

    targets: list[tuple[str, Path, Path]] = []
    if gate_verdict_path is not None and verdict_display_path is not None:
        targets.append((verdict_label, verdict_display_path, gate_verdict_path))
    if manifest_present and manifest_path is not None:
        targets.append(("manifest", manifest_path, manifest_path))
    if intent_target is not None:
        targets.append(("intent", intent_target, intent_target))
    if waivers_target is not None:
        targets.append(("waivers", waivers_target, waivers_target))

    seen: set[str] = set()
    for label, display_path, open_path in targets:
        display_resolved = display_path.resolve()
        open_resolved = open_path.resolve()
        dedupe_key = f"{label}:{display_resolved}:{open_resolved}"
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        lines.append(f"  {label}: {safe_relpath(repo_root, display_resolved)}")
        if show_all_open:
            mac, linux, windows = _open_command_lines(path=open_resolved)
            lines.append(f"    open_macos: {mac}")
            lines.append(f"    open_linux: {linux}")
            lines.append(f"    open_windows: {windows}")
        else:
            platform_name, cmd = _open_command_for_platform(path=open_resolved, family=family)
            lines.append(f"    open_{platform_name}: {cmd}")

    if verbose:
        lines.append("")
        lines.append("details:")
        if run_ref:
            lines.append(f"  run: {run_ref}")
        if run_key:
            lines.append(f"  run_key: {run_key}")
        if attempt_id:
            lines.append(f"  attempt_id: {attempt_id}")
        if attempt_dir is not None:
            lines.append(f"  attempt_dir: {safe_relpath(repo_root, attempt_dir)}")
        if chain_out_dir is not None:
            lines.append(f"  out_dir: {safe_relpath(repo_root, chain_out_dir)}")

    level = "GO" if verdict == "GO" else "NO-GO"
    _emit_human_status(prefix="[belgi verify]", level=level, lines=lines)


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

    verdict_raw = summary.get("verdict")
    if verdict_raw is not None:
        if not isinstance(verdict_raw, str) or verdict_raw not in ("GO", "NO-GO"):
            raise ValueError("run.summary.json verdict missing/invalid")
        if verdict_raw == "NO-GO":
            reason_raw = summary.get("primary_reason")
            reason = str(reason_raw).strip() if isinstance(reason_raw, str) else ""
            if not reason:
                reason = "attempt finalized as NO-GO"
            raise ValueError(f"attempt {run_key}/{attempt_id} is NO-GO: {reason}")

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
    from belgi.core.jail import resolve_repo_rel_path

    repo_root = Path(str(args.repo)).resolve()
    run_ref: str | None = None
    run_key: str | None = None
    attempt_id: str | None = None
    selected_by = "latest"
    workspace_dir: Path | None = None
    attempt_dir: Path | None = None

    try:
        if not repo_root.exists():
            raise _UserInputError(f"repo path does not exist: {repo_root}")
        if not repo_root.is_dir():
            raise _UserInputError(f"repo path is not a directory: {repo_root}")
        if repo_root.is_symlink():
            raise _UserInputError(f"symlink repo root not allowed: {repo_root}")

        in_arg = str(getattr(args, "input", "") or "").strip()
        run_key_arg = str(getattr(args, "run_key", "") or "").strip()
        attempt_id_arg = str(getattr(args, "attempt_id", "") or "").strip()
        if in_arg and (run_key_arg or attempt_id_arg):
            raise _UserInputError("--in cannot be used with --run-key/--attempt-id")

        try:
            _, workspace_dir = _resolve_workspace_dir(
                repo_root,
                getattr(args, "workspace", DEFAULT_WORKSPACE_REL),
                must_exist=True,
            )
            _migrate_legacy_run_key_dirs(
                workspace_runs_dir=workspace_dir / "runs",
                store_runs_dir=_resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=False),
                repo_root=repo_root,
            )
            store_runs_dir = _resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=True)
        except ValueError as e:
            raise _UserInputError(str(e)) from e

        input_target: Path | None = None
        if in_arg:
            try:
                input_target = resolve_repo_rel_path(
                    repo_root,
                    in_arg,
                    must_exist=True,
                    must_be_file=None,
                    allow_backslashes=False,
                    forbid_symlinks=True,
                )
            except ValueError as e:
                raise _UserInputError(str(e)) from e

        attempt_dir, selected_by, run_ref = _select_verify_attempt_dir(
            repo_root=repo_root,
            workspace_dir=workspace_dir,
            store_runs_dir=store_runs_dir,
            input_target=input_target,
            run_key_arg=run_key_arg or None,
            attempt_id_arg=attempt_id_arg or None,
        )
        run_key, attempt_id = _verify_attempt_dir(repo_root, attempt_dir)
        if run_ref is None:
            run_ref, _ = _resolve_run_workspace_for_attempt(
                workspace_dir=workspace_dir,
                run_key=run_key,
                attempt_id=attempt_id,
            )

    except _UserInputError as e:
        _emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=None,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        _emit_human_status(prefix="[belgi verify]", level="USER_ERROR", lines=[str(e)])
        return RC_USER_ERROR
    except ValueError as e:
        next_instruction = _verify_next_instruction(
            chain_out_dir=(attempt_dir / "repo" / "out") if attempt_dir is not None else None,
            primary_reason=str(e),
        )
        _emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=None,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        run_workspace_dir = None
        if workspace_dir is not None and run_ref:
            run_workspace_dir = workspace_dir / "runs" / run_ref
        _emit_verify_result_block(
            repo_root=repo_root,
            verdict="NO-GO",
            selected_by=selected_by,
            run_ref=run_ref,
            run_key=run_key,
            attempt_id=attempt_id,
            primary_reason=str(e),
            next_instruction=next_instruction,
            attempt_dir=attempt_dir,
            run_workspace_dir=run_workspace_dir,
            verbose=bool(getattr(args, "verbose", False)),
        )
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
        _emit_human_status(prefix="[belgi verify]", level="INTERNAL_ERROR", lines=[str(e)])
        return RC_INTERNAL_ERROR

    _emit_machine_result(
        ok=True,
        verdict="GO",
        primary_reason="",
        tier_id=None,
        run_key=run_key,
        attempt_id=attempt_id,
    )
    run_workspace_dir = None
    if workspace_dir is not None and run_ref:
        run_workspace_dir = workspace_dir / "runs" / run_ref
    _emit_verify_result_block(
        repo_root=repo_root,
        verdict="GO",
        selected_by=selected_by,
        run_ref=run_ref,
        run_key=run_key,
        attempt_id=attempt_id,
        primary_reason="verification checks passed",
        next_instruction="No action required.",
        attempt_dir=attempt_dir,
        run_workspace_dir=run_workspace_dir,
        verbose=bool(getattr(args, "verbose", False)),
    )
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
    protocol: Any | None = None
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

        if not isinstance(obj_hash, str) or not is_hex_sha256(obj_hash):
            failures.append(f"{field}.hash: invalid SHA-256 format")
            return False, ""
        declared_hash = obj_hash.lower()
        
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
        if computed != declared_hash:
            failures.append(
                f"{field}: hash mismatch for {target_path.name} "
                f"(declared={declared_hash[:16]}..., computed={computed[:16]}...)"
            )
            return False, ""

        return True, declared_hash
    
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

        if not isinstance(declared_seal_hash, str) or not is_hex_sha256(declared_seal_hash):
            failures.append("SealManifest.seal_hash: invalid or missing SHA-256")
        elif not final_commit_sha:
            failures.append("SealManifest.final_commit_sha: missing or empty")
        elif not run_id:
            failures.append("SealManifest.run_id: missing or empty")
        else:
            declared_seal_hash = declared_seal_hash.lower()
            try:
                computed_seal = canonical_seal_hash(dict(seal_manifest))
            except Exception as e:
                failures.append(f"seal_hash recomputation failed: {e}")
            else:
                computed_seal_l = computed_seal.lower()
                if computed_seal_l == declared_seal_hash:
                    checks_passed += 1
                else:
                    failures.append(
                        f"seal_hash mismatch: declared={declared_seal_hash[:16]}..., "
                        f"computed={computed_seal_l[:16]}..."
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
    if protocol is None:
        print("[belgi bundle check] ERROR: builtin protocol context unavailable", file=sys.stderr)
        return 1
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
    parser = _BelgiArgumentParser(
        prog="belgi",
        description="BELGI CLI — Protocol pack management and evidence generation tools",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    # about
    subparsers.add_parser("about", help="[Tier A] Print package identity info")

    # init
    p_init = subparsers.add_parser("init", help="[Tier A] Initialize BELGI adopter defaults in a repository")
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
    p_policy = subparsers.add_parser("policy", help="[Tier B] Policy helper commands")
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
    p_run = subparsers.add_parser("run", help="[Tier A] Run workspace helper commands")
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
    p_run.add_argument(
        "--base-revision",
        default=None,
        help=(
            "Optional 40-hex base commit SHA used only when CI base env and upstream merge-base "
            "discovery are unavailable"
        ),
    )
    p_run.add_argument("--verbose", action="store_true", help="Verbose human output (deep paths and full open helpers)")
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

    # waiver (subparser group)
    p_waiver = subparsers.add_parser("waiver", help="[Tier A] Waiver wizard helpers (human-controlled)")
    waiver_subs = p_waiver.add_subparsers(dest="waiver_command", help="Waiver subcommand")

    p_waiver_new = waiver_subs.add_parser("new", help="Create a schema-valid waiver draft JSON")
    p_waiver_new.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_waiver_new.add_argument(
        "--workspace",
        default=DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {DEFAULT_WORKSPACE_REL})",
    )
    p_waiver_new.add_argument("--run-id", required=True, help="Run workspace identifier")
    p_waiver_new.add_argument("--gate", required=True, choices=("Q", "R"), help="Gate identifier")
    p_waiver_new.add_argument("--rule-id", required=True, help="Rule identifier for this waiver")
    p_waiver_new.add_argument("--waiver-id", required=True, help="Deterministic waiver id")
    p_waiver_new.add_argument("--expires-at", required=True, help="RFC3339 expiry timestamp")
    p_waiver_new.add_argument(
        "--out",
        default=None,
        help="Optional repo-relative output path (default: .belgi/runs/<run_id>/inputs/waivers/<waiver_id>.json)",
    )
    p_waiver_new.add_argument("--force", action="store_true", help="Overwrite output if it already exists")

    p_waiver_apply = waiver_subs.add_parser(
        "apply", help="Record a waiver reference in run-local waiver inputs for C1 consumption"
    )
    p_waiver_apply.add_argument("--repo", default=".", help="Repo root (default: .)")
    p_waiver_apply.add_argument(
        "--workspace",
        default=DEFAULT_WORKSPACE_REL,
        help=f"Repo-relative workspace root (default: {DEFAULT_WORKSPACE_REL})",
    )
    p_waiver_apply.add_argument("--run-id", required=True, help="Run workspace identifier")
    p_waiver_apply.add_argument("--waiver", required=True, help="Repo-relative path to waiver JSON")

    # verify
    p_verify = subparsers.add_parser("verify", help="[Tier A] Verify deterministic run summaries and manifests")
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
    p_verify.add_argument(
        "--run-key",
        default=None,
        help="Explicit run_key to verify (64 lowercase hex)",
    )
    p_verify.add_argument(
        "--attempt-id",
        default=None,
        help="Explicit attempt id to verify (default: latest attempt for run_key)",
    )
    p_verify.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose human output (full paths and expanded open helpers)",
    )

    # manifest (subparser group)
    p_manifest = subparsers.add_parser("manifest", help="[Tier C] EvidenceManifest mutation helpers")
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
    p_pack = subparsers.add_parser("pack", help="[Tier B] Protocol pack management commands")
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
    p_bundle = subparsers.add_parser("bundle", help="[Tier B] Evidence bundle commands")
    bundle_subs = p_bundle.add_subparsers(dest="bundle_command", help="Bundle subcommand")
    
    # bundle check
    p_bundle_check = bundle_subs.add_parser("check", help="Check an evidence bundle (demo-grade checker)")
    p_bundle_check.add_argument("--in", dest="input", required=True, help="Bundle directory to check")
    p_bundle_check.add_argument(
        "--demo", action="store_true",
        help="Acknowledge this is a demo-grade checker (required)"
    )
    p_bundle_check.add_argument("--verbose", action="store_true", help="Verbose output")

    # stage (strict forwarders to canonical chain entrypoints)
    p_stage = subparsers.add_parser(
        "stage",
        help="[Tier C] Run repo-local stage forwarders (thin wrappers only)",
        description=_STAGE_FORWARDER_NOTE,
        epilog=(
            "Use `belgi run` for end-to-end canonical spine execution. "
            "Use `belgi stage` for targeted stage operations."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    stage_subs = p_stage.add_subparsers(dest="stage_command", help="Stage subcommand")

    p_stage_c1 = stage_subs.add_parser(
        "c1",
        help="Forward to chain.compiler_c1_intent",
        epilog=(
            f"{_STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage c1 --repo . --intent-spec IntentSpec.core.md --out out/LockedSpec.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_q = stage_subs.add_parser(
        "q",
        help="Forward to chain.gate_q_verify",
        epilog=(
            f"{_STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage q --repo . --intent-spec IntentSpec.core.md "
            "--locked-spec out/LockedSpec.json --evidence-manifest out/EvidenceManifest.json "
            "--out out/GateVerdict.Q.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_r = stage_subs.add_parser(
        "r",
        help="Forward to chain.gate_r_verify",
        epilog=(
            f"{_STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage r --repo . --locked-spec out/LockedSpec.json "
            "--gate-q-verdict out/GateVerdict.Q.json --evidence-manifest out/EvidenceManifest.json "
            "--evaluated-revision <sha40> --out out/verify_report.R.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_c3 = stage_subs.add_parser(
        "c3",
        help="Forward to chain.compiler_c3_docs",
        epilog=(
            f"{_STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage c3 --repo . --locked-spec out/LockedSpec.json "
            "--gate-q-verdict out/GateVerdict.Q.json --gate-r-verdict out/GateVerdict.R.json "
            "--r-snapshot-manifest out/EvidenceManifest.R.json --out-final-manifest out/EvidenceManifest.json "
            "--out-log docs/docs_compilation_log.json --out-docs docs/chain_of_changes.md "
            "--out-bundle-dir out/bundle --out-bundle-root-sha out/bundle_root.sha256 "
            "--prompt-block-hashes out/prompt_block_hashes.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_s = stage_subs.add_parser(
        "s",
        help="Stage S subcommands (seal/verify)",
        description=_STAGE_FORWARDER_NOTE,
        epilog="Choose `seal` or `verify` for targeted Stage S operations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    stage_s_subs = p_stage_s.add_subparsers(dest="stage_s_command", help="S subcommand")

    p_stage_s_seal = stage_s_subs.add_parser(
        "seal",
        help="Forward to chain.seal_bundle",
        epilog=(
            f"{_STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage s seal --repo . --locked-spec out/LockedSpec.json "
            "--gate-q-verdict out/GateVerdict.Q.json --gate-r-verdict out/GateVerdict.R.json "
            "--evidence-manifest out/EvidenceManifest.json --final-commit-sha <sha40> "
            "--sealed-at 1970-01-01T00:00:00Z --signer human:ops --out out/SealManifest.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_stage_s_verify = stage_s_subs.add_parser(
        "verify",
        help="Forward to chain.gate_s_verify",
        epilog=(
            f"{_STAGE_FORWARDER_NOTE}\n\n"
            "Abbreviated example (source checkout): "
            "belgi stage s verify --repo . --locked-spec out/LockedSpec.json "
            "--seal-manifest out/SealManifest.json --evidence-manifest out/EvidenceManifest.json "
            "--out out/GateVerdict.S.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # supplychain-scan
    p_sc = subparsers.add_parser(
        "supplychain-scan",
        help="[Tier C] Run supplychain scan and produce policy.supplychain artifact",
    )
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
    p_adv = subparsers.add_parser(
        "adversarial-scan",
        help="[Tier C] Run adversarial scan and produce policy.adversarial_scan artifact",
    )
    p_adv.add_argument("--repo", default=".", help="Repo root")
    p_adv.add_argument("--run-id", default="unknown", help="Run ID to embed in the PolicyReportPayload (default: unknown)")
    p_adv.add_argument(
        "--out",
        default="out/policy-adversarial-scan.json",
        help="Output JSON path (default: out/policy-adversarial-scan.json)",
    )
    p_adv.add_argument("--deterministic", action="store_true", help="Use fixed timestamps for deterministic output")
    p_adv.set_defaults(func=cmd_adversarial_scan)

    try:
        args, unknown_args = parser.parse_known_args(argv)
    except _CliUsageError as e:
        return _emit_cli_user_error_result(
            primary_reason=e.message or "invalid CLI usage",
            parser=e.parser if isinstance(e.parser, argparse.ArgumentParser) else parser,
        )
    except SystemExit as e:
        # Keep argparse --help semantics as a non-error exit.
        code = e.code if isinstance(e.code, int) else 1
        if code == 0:
            return RC_GO
        return _emit_cli_user_error_result(
            primary_reason=f"argument parsing failed (rc={code})",
            parser=parser,
        )

    if args.command == "stage":
        setattr(args, "forward_args", [str(x) for x in unknown_args])
    elif unknown_args:
        return _emit_cli_user_error_result(
            primary_reason=f"unrecognized arguments: {' '.join(str(x) for x in unknown_args)}",
            parser=parser,
        )
    
    if args.command == "about":
        rc = cmd_about(args)
    elif args.command == "pack":
        if args.pack_command == "build":
            if not args.input:
                rc = _emit_cli_user_error_result(
                    primary_reason="--in required for `belgi pack build`",
                    parser=p_pack_build,
                )
            else:
                rc = cmd_pack_build(args)
        elif args.pack_command == "verify":
            rc = cmd_pack_verify(args)
        else:
            rc = _emit_cli_user_error_result(
                primary_reason="missing pack subcommand",
                parser=p_pack,
                help_to_stderr=True,
            )
    elif args.command == "init":
        rc = cmd_init(args)
    elif args.command == "policy":
        if args.policy_command in ("stub", "check-overlay"):
            rc = int(args.func(args))
        else:
            rc = _emit_cli_user_error_result(
                primary_reason="missing policy subcommand",
                parser=p_policy,
                help_to_stderr=True,
            )
    elif args.command == "run":
        if args.run_command == "new":
            rc = cmd_run_new(args)
        elif getattr(args, "tier", None):
            rc = cmd_run(args)
        else:
            rc = _emit_cli_user_error_result(
                primary_reason="missing run mode: provide `run new` or `run --tier`",
                parser=p_run,
                help_to_stderr=True,
            )
    elif args.command == "waiver":
        if args.waiver_command == "new":
            rc = cmd_waiver_new(args)
        elif args.waiver_command == "apply":
            rc = cmd_waiver_apply(args)
        else:
            rc = _emit_cli_user_error_result(
                primary_reason="missing waiver subcommand",
                parser=p_waiver,
                help_to_stderr=True,
            )
    elif args.command == "verify":
        rc = cmd_verify(args)
    elif args.command == "manifest":
        if args.manifest_command == "add":
            rc = cmd_manifest_add(args)
        else:
            rc = _emit_cli_user_error_result(
                primary_reason="missing manifest subcommand",
                parser=p_manifest,
                help_to_stderr=True,
            )
    elif args.command == "bundle":
        if args.bundle_command == "check":
            rc = cmd_bundle_check(args)
        else:
            rc = _emit_cli_user_error_result(
                primary_reason="missing bundle subcommand",
                parser=p_bundle,
                help_to_stderr=True,
            )
    elif args.command == "stage":
        stage_forward_args = [str(x) for x in (getattr(args, "forward_args", []) or [])]
        if args.stage_command == "c1":
            rc = _run_stage_forwarder(
                stage_name="c1",
                parser=p_stage_c1,
                module_name="chain.compiler_c1_intent",
                forward_args=stage_forward_args,
            )
        elif args.stage_command == "q":
            rc = _run_stage_forwarder(
                stage_name="q",
                parser=p_stage_q,
                module_name="chain.gate_q_verify",
                forward_args=stage_forward_args,
            )
        elif args.stage_command == "r":
            rc = _run_stage_forwarder(
                stage_name="r",
                parser=p_stage_r,
                module_name="chain.gate_r_verify",
                forward_args=stage_forward_args,
            )
        elif args.stage_command == "c3":
            rc = _run_stage_forwarder(
                stage_name="c3",
                parser=p_stage_c3,
                module_name="chain.compiler_c3_docs",
                forward_args=stage_forward_args,
            )
        elif args.stage_command == "s":
            if args.stage_s_command == "seal":
                rc = _run_stage_forwarder(
                    stage_name="s seal",
                    parser=p_stage_s_seal,
                    module_name="chain.seal_bundle",
                    forward_args=stage_forward_args,
                )
            elif args.stage_s_command == "verify":
                rc = _run_stage_forwarder(
                    stage_name="s verify",
                    parser=p_stage_s_verify,
                    module_name="chain.gate_s_verify",
                    forward_args=stage_forward_args,
                )
            else:
                rc = _emit_cli_user_error_result(
                    primary_reason="missing stage s subcommand",
                    parser=p_stage_s,
                    help_to_stderr=True,
                )
        else:
            rc = _emit_cli_user_error_result(
                primary_reason="missing stage subcommand",
                parser=p_stage,
                help_to_stderr=True,
            )
    elif args.command == "supplychain-scan":
        rc = int(args.func(args))
    elif args.command == "adversarial-scan":
        rc = int(args.func(args))
    else:
        rc = _emit_cli_user_error_result(
            primary_reason="missing command",
            parser=parser,
            help_to_stderr=True,
        )

    return _normalize_cli_exit_code(int(rc))


if __name__ == "__main__":
    sys.exit(main())
