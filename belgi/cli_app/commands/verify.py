from __future__ import annotations

import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

import belgi.cli_app.commands.run as run_commands
from belgi.cli_app import render as cli_render


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
        if target.name != run_commands.RUN_SUMMARY_FILENAME:
            raise ValueError("--in file path must be run.summary.json")
        return [target.parent]
    if not target.is_dir():
        raise ValueError(f"--in path is not a file or directory: {target}")

    summary_here = target / run_commands.RUN_SUMMARY_FILENAME
    if summary_here.exists():
        if summary_here.is_symlink() or not summary_here.is_file():
            raise ValueError(f"invalid summary path: {summary_here}")
        return [target]

    first_level = _list_dirs_sorted(target)
    if not first_level:
        raise ValueError(f"no run attempts found under: {target}")

    direct_attempts = [d for d in first_level if (d / run_commands.RUN_SUMMARY_FILENAME).is_file()]
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
            summary_path = attempt_dir / run_commands.RUN_SUMMARY_FILENAME
            if not summary_path.exists() or summary_path.is_symlink() or not summary_path.is_file():
                raise ValueError(f"missing run summary: {summary_path}")
            attempts.append(attempt_dir)
    return attempts

def _validate_run_key_arg(raw: str) -> str:
    run_key = str(raw or "").strip().lower()
    if not run_key:
        raise run_commands._UserInputError("--run-key missing/invalid")
    if run_commands.RUN_KEY_DIR_PATTERN.fullmatch(run_key) is None:
        raise run_commands._UserInputError("--run-key must be 64 lowercase hex")
    return run_key

def _validate_attempt_id_arg(raw: str) -> str:
    attempt_id = str(raw or "").strip()
    if not attempt_id:
        raise run_commands._UserInputError("--attempt-id missing/invalid")
    if run_commands.ATTEMPT_ID_PATTERN.fullmatch(attempt_id) is None:
        raise run_commands._UserInputError("--attempt-id must match attempt-0001 format")
    return attempt_id

def _max_attempt_id_in_run_key_dir(run_key_dir: Path) -> str:
    if run_key_dir.is_symlink() or not run_key_dir.is_dir():
        raise run_commands._UserInputError(f"invalid run_key directory: {run_key_dir}")
    best: int | None = None
    for child in _list_dirs_sorted(run_key_dir):
        m = run_commands.ATTEMPT_ID_PATTERN.fullmatch(child.name)
        if m is None:
            raise run_commands._UserInputError(f"unexpected attempt directory name: {child.name}")
        idx = int(m.group(1))
        best = idx if best is None or idx > best else best
    if best is None:
        raise run_commands._UserInputError(f"run_key has no attempts: {run_key_dir.name}")
    return f"attempt-{best:04d}"

def _read_pointer_text(path: Path, *, label: str) -> str:
    if not path.exists():
        raise run_commands._UserInputError(f"{label} missing: {path}")
    if path.is_symlink() or not path.is_file():
        raise run_commands._UserInputError(f"{label} invalid path type: {path}")
    value = path.read_text(encoding="utf-8", errors="strict").strip()
    if not value:
        raise run_commands._UserInputError(f"{label} empty: {path}")
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
            raise run_commands._UserInputError(
                "--in must resolve to exactly one attempt directory; "
                "use --run-key/--attempt-id for explicit selection"
            )
        return attempt_dirs[0], "explicit", None

    if attempt_id_arg and not run_key_arg:
        raise run_commands._UserInputError("--attempt-id requires --run-key")

    if run_key_arg:
        run_key = _validate_run_key_arg(run_key_arg)
        run_key_dir = store_runs_dir / run_key
        if not run_key_dir.exists() or run_key_dir.is_symlink() or not run_key_dir.is_dir():
            raise run_commands._UserInputError(f"run_key missing: {run_key}")
        if attempt_id_arg:
            attempt_id = _validate_attempt_id_arg(attempt_id_arg)
        else:
            attempt_id = _max_attempt_id_in_run_key_dir(run_key_dir)
        attempt_dir = run_key_dir / attempt_id
        if not attempt_dir.exists() or attempt_dir.is_symlink() or not attempt_dir.is_dir():
            raise run_commands._UserInputError(f"attempt missing for run_key {run_key}: {attempt_id}")
        return attempt_dir, "explicit", None

    runs_dir = workspace_dir / "runs"
    if runs_dir.exists():
        candidates: list[tuple[str, Path]] = []
        for run_dir in _list_dirs_sorted(runs_dir):
            run_id = run_dir.name
            run_key_path = run_commands._run_pointer_run_key_path(run_dir)
            last_attempt_path = run_commands._run_pointer_last_attempt_path(run_dir)
            if not run_key_path.exists() or not last_attempt_path.exists():
                continue
            try:
                attempt_id = _validate_attempt_id_arg(
                    _read_pointer_text(last_attempt_path, label=f"{run_id} last_attempt")
                )
                run_key = _validate_run_key_arg(_read_pointer_text(run_key_path, label=f"{run_id} run_key"))
            except run_commands._UserInputError:
                continue
            attempt_dir = store_runs_dir / run_key / attempt_id
            if not attempt_dir.exists() or attempt_dir.is_symlink() or not attempt_dir.is_dir():
                continue
            candidates.append((run_id, attempt_dir))
        if candidates:
            candidates.sort(key=lambda item: item[0])
            run_id, attempt_dir = candidates[-1]
            return attempt_dir, "pointer", run_id

    run_key_dirs = _list_dirs_sorted(store_runs_dir)
    run_key_candidates: list[Path] = []
    for run_key_dir in run_key_dirs:
        if run_commands.RUN_KEY_DIR_PATTERN.fullmatch(run_key_dir.name.lower()) is None:
            raise run_commands._UserInputError(f"unexpected store run_key directory name: {run_key_dir.name}")
        run_key_candidates.append(run_key_dir)
    if not run_key_candidates:
        raise run_commands._UserInputError("no valid pointer target and no run attempts found under .belgi/store/runs")
    run_key_candidates.sort(key=lambda p: p.name)
    latest_run_key_dir = run_key_candidates[-1]
    latest_attempt_id = _max_attempt_id_in_run_key_dir(latest_run_key_dir)
    return latest_run_key_dir / latest_attempt_id, "store", None

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
        run_key_path = run_commands._run_pointer_run_key_path(run_dir)
        last_attempt_path = run_commands._run_pointer_last_attempt_path(run_dir)
        if not run_key_path.exists() or not last_attempt_path.exists():
            continue
        try:
            pointer_run_key = _validate_run_key_arg(_read_pointer_text(run_key_path, label=f"{run_id} run_key"))
            pointer_attempt = _validate_attempt_id_arg(
                _read_pointer_text(last_attempt_path, label=f"{run_id} last_attempt")
            )
        except run_commands._UserInputError:
            continue
        if pointer_run_key == run_key and pointer_attempt == attempt_id:
            matches.append((run_id, run_dir))
    if not matches:
        return None, None
    matches.sort(key=lambda item: item[0])
    return matches[-1]

def _verify_next_instruction(*, chain_out_dir: Path | None, primary_reason: str) -> str:
    if "EvidenceManifest.anchored_time_utc" in primary_reason:
        return (
            "Do re-run `belgi run` with BELGI >=1.4.2 so EvidenceManifest.anchored_time_utc is recorded, "
            "then re-run `belgi verify`."
        )
    for gate_name in run_commands._preferred_gate_verdict_order(primary_reason):
        gate_path = chain_out_dir / gate_name if chain_out_dir is not None else None
        if gate_path is not None:
            next_instruction = run_commands._load_next_instruction_from_gate_verdict(gate_path)
            if next_instruction:
                return next_instruction
    parse_next = run_commands._load_next_instruction_from_c1_parse_diagnostic(chain_out_dir)
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

    family = run_commands._platform_family()
    show_all_open = run_commands._show_all_open_helpers(verbose=verbose)
    chain_out_dir = attempt_dir / "repo" / "out" if attempt_dir is not None else None
    if chain_out_dir is not None and (
        not chain_out_dir.exists() or chain_out_dir.is_symlink() or not chain_out_dir.is_dir()
    ):
        chain_out_dir = None

    gate_verdict_path = run_commands._primary_gate_verdict_path(chain_out_dir, primary_reason=primary_reason)
    primary_gate = run_commands._gate_letter_from_verdict_path(gate_verdict_path) or "R"
    gate_paths = run_commands._gate_verdict_paths(chain_out_dir)
    gate_status_raw = run_commands._gate_status_map(gate_paths)
    gate_status = {
        gate: (gate_status_raw[gate] if gate_status_raw[gate] in {"GO", "NO-GO"} else "missing")
        for gate in ("Q", "R", "S")
    }

    manifest_path = run_commands._evidence_manifest_path(chain_out_dir)
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

    verdict_ptr, _ = run_commands._run_workspace_pointer_targets(run_workspace_dir)
    verdict_display_path = verdict_ptr if (verdict_ptr is not None and not verbose) else gate_verdict_path

    intent_target: Path | None = None
    waivers_target: Path | None = None
    if run_workspace_dir is not None:
        maybe_intent = run_commands._run_intent_path(run_workspace_dir)
        if maybe_intent.exists() and not maybe_intent.is_symlink() and maybe_intent.is_file():
            intent_target = maybe_intent
        maybe_waivers = run_commands._run_waivers_dir(run_workspace_dir)
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
        f"verified_key={run_commands._short_run_key(run_key) or 'UNKNOWN'}",
        f"verified_attempt={run_commands._short_attempt_id(attempt_id) or 'UNKNOWN'}",
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
            mac, linux, windows = run_commands._open_command_lines(path=open_resolved)
            lines.append(f"    open_macos: {mac}")
            lines.append(f"    open_linux: {linux}")
            lines.append(f"    open_windows: {windows}")
        else:
            platform_name, cmd = run_commands._open_command_for_platform(path=open_resolved, family=family)
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
    cli_render._emit_human_status(prefix="[belgi verify]", level=level, lines=lines)

def _parse_rfc3339_dt_utc(raw: str, *, field: str) -> datetime:
    value = str(raw or "").strip()
    if run_commands._RFC3339_UTC_RE.fullmatch(value) is None:
        raise ValueError(f"{field} missing/invalid RFC3339 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"{field} missing timezone offset")
    return parsed.astimezone(timezone.utc)

def _verify_waiver_expiry_anchor(
    *,
    attempt_dir: Path,
    evidence_obj: dict[str, object],
) -> None:
    from belgi.core.jail import resolve_repo_rel_path

    attempt_repo_root = attempt_dir / "repo"
    attempt_out_dir = attempt_repo_root / "out"
    locked_spec_path = attempt_out_dir / "LockedSpec.json"
    if not locked_spec_path.exists() or locked_spec_path.is_symlink() or not locked_spec_path.is_file():
        raise ValueError("LockedSpec.json missing; cannot validate waiver expiry against anchored_time_utc")

    locked_spec = run_commands._load_json_object(locked_spec_path, label="LockedSpec.json")
    waivers = locked_spec.get("waivers_applied")
    if not isinstance(waivers, list) or len(waivers) == 0:
        return

    anchored_time_raw = evidence_obj.get("anchored_time_utc")
    if not isinstance(anchored_time_raw, str) or not anchored_time_raw.strip():
        raise ValueError(
            "waiver expiry validation requires EvidenceManifest.anchored_time_utc; "
            "re-run with BELGI >=1.4.2 to regenerate evidence, then re-run `belgi verify`"
        )
    try:
        anchored_time = _parse_rfc3339_dt_utc(anchored_time_raw, field="EvidenceManifest.anchored_time_utc")
    except ValueError:
        raise ValueError(
            "waiver expiry validation requires valid EvidenceManifest.anchored_time_utc; "
            "re-run with BELGI >=1.4.2 to regenerate evidence, then re-run `belgi verify`"
        ) from None

    for idx, waiver_rel in enumerate(waivers):
        if not isinstance(waiver_rel, str) or not waiver_rel.strip():
            raise ValueError(f"LockedSpec.waivers_applied[{idx}] missing/invalid")

        waiver_path = resolve_repo_rel_path(
            attempt_repo_root,
            waiver_rel.strip(),
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        waiver_obj = run_commands._load_json_object(waiver_path, label=f"Waiver[{idx}]")
        expires_at_raw = waiver_obj.get("expires_at")
        if not isinstance(expires_at_raw, str) or not expires_at_raw.strip():
            raise ValueError(f"waiver '{waiver_rel.strip()}' expires_at missing/invalid")
        expires_at = _parse_rfc3339_dt_utc(expires_at_raw, field=f"{waiver_rel.strip()} expires_at")
        if not (expires_at > anchored_time):
            raise ValueError(
                f"waiver '{waiver_rel.strip()}' expires_at is not after EvidenceManifest.anchored_time_utc"
            )

def _verify_attempt_dir(repo_root: Path, attempt_dir: Path) -> tuple[str, str]:
    from belgi.core.hash import sha256_bytes
    from belgi.core.jail import resolve_repo_rel_path
    from belgi.core.schema import validate_schema
    from belgi.protocol.pack import get_builtin_protocol_context

    summary_path = attempt_dir / run_commands.RUN_SUMMARY_FILENAME
    if not summary_path.exists() or summary_path.is_symlink() or not summary_path.is_file():
        raise ValueError(f"missing run summary: {summary_path}")
    summary = run_commands._load_json_object(summary_path, label=run_commands.RUN_SUMMARY_FILENAME)

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
    if run_commands._compute_run_key_from_preimage(preimage) != run_key:
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

    evidence_obj = run_commands._load_json_object(evidence_manifest_path, label="EvidenceManifest.json")
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

    _verify_waiver_expiry_anchor(attempt_dir=attempt_dir, evidence_obj=evidence_obj)

    return run_key, attempt_id

def cmd_verify(args: argparse.Namespace) -> int:
    from belgi.core.jail import resolve_repo_rel_path

    repo_root = Path(str(args.repo)).resolve()
    run_ref: str | None = None
    run_key: str | None = None
    attempt_id: str | None = None
    selected_by = "store"
    workspace_dir: Path | None = None
    attempt_dir: Path | None = None

    try:
        if not repo_root.exists():
            raise run_commands._UserInputError(f"repo path does not exist: {repo_root}")
        if not repo_root.is_dir():
            raise run_commands._UserInputError(f"repo path is not a directory: {repo_root}")
        if repo_root.is_symlink():
            raise run_commands._UserInputError(f"symlink repo root not allowed: {repo_root}")

        in_arg = str(getattr(args, "input", "") or "").strip()
        run_key_arg = str(getattr(args, "run_key", "") or "").strip()
        attempt_id_arg = str(getattr(args, "attempt_id", "") or "").strip()
        if in_arg and (run_key_arg or attempt_id_arg):
            raise run_commands._UserInputError("--in cannot be used with --run-key/--attempt-id")

        try:
            _, workspace_dir = run_commands._resolve_workspace_dir(
                repo_root,
                getattr(args, "workspace", run_commands.DEFAULT_WORKSPACE_REL),
                must_exist=True,
            )
            run_commands._migrate_legacy_run_key_dirs(
                workspace_runs_dir=workspace_dir / "runs",
                store_runs_dir=run_commands._resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=False),
                repo_root=repo_root,
            )
            store_runs_dir = run_commands._resolve_store_runs_dir(workspace_dir=workspace_dir, must_exist=True)
        except ValueError as e:
            raise run_commands._UserInputError(str(e)) from e

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
                raise run_commands._UserInputError(str(e)) from e

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

    except run_commands._UserInputError as e:
        cli_render._emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=None,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        cli_render._emit_human_status(prefix="[belgi verify]", level="USER_ERROR", lines=[str(e)])
        return cli_render.RC_USER_ERROR
    except ValueError as e:
        next_instruction = _verify_next_instruction(
            chain_out_dir=(attempt_dir / "repo" / "out") if attempt_dir is not None else None,
            primary_reason=str(e),
        )
        cli_render._emit_machine_result(
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
        return cli_render.RC_NO_GO
    except Exception as e:
        cli_render._emit_machine_result(
            ok=False,
            verdict="NO-GO",
            primary_reason=str(e),
            tier_id=None,
            run_key=run_key,
            attempt_id=attempt_id,
        )
        cli_render._emit_human_status(prefix="[belgi verify]", level="INTERNAL_ERROR", lines=[str(e)])
        return cli_render.RC_INTERNAL_ERROR

    cli_render._emit_machine_result(
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
    return cli_render.RC_GO
