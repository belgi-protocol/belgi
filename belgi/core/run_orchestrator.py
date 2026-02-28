from __future__ import annotations

import importlib
import inspect
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from importlib.resources import files as resource_files
from pathlib import Path
from typing import Any

from belgi.commands.adversarial_scan import run_adversarial_scan
from belgi.commands.supplychain_scan import run_supplychain_scan
from belgi.core.command_log import append_command_to_manifest
from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.schema import validate_schema


CHAIN_REPO_DIRNAME = "repo"
CHAIN_OUT_DIRNAME = "out"
FIXED_GENERATED_AT = "1970-01-01T00:00:00Z"
FIXED_SEALED_AT = "2000-01-01T00:30:00Z"
FIXED_SIGNER = "human:belgi-run"

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA1_40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_CHAIN_TEMPLATE_BINDINGS: tuple[tuple[str, str], ...] = (
    ("templates/PromptBundle.blocks.md", "belgi/templates/PromptBundle.blocks.md"),
    ("templates/DocsCompiler.template.md", "belgi/templates/DocsCompiler.template.md"),
)
_C3_CANONICAL_STAGE_ROOT_REPO_REL = ".belgi/engine/c3_canonicals"
_APPLIED_WAIVERS_SOURCE_REPO_REL = ".belgi/waivers_applied"
_APPLIED_WAIVERS_STAGE_REPO_REL = f"{CHAIN_OUT_DIRNAME}/inputs/waivers_applied"
_C3_CANONICAL_PACKAGE_BINDINGS: tuple[tuple[str, str], ...] = (
    ("canonicals/CANONICALS.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/CANONICALS.md"),
    ("canonicals/terminology.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/terminology.md"),
    ("canonicals/trust-model.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/trust-model.md"),
    (
        "canonicals/docs/operations/consistency-sweep.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/operations/consistency-sweep.md",
    ),
    (
        "canonicals/docs/operations/evidence-bundles.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/operations/evidence-bundles.md",
    ),
    (
        "canonicals/docs/operations/evidence-ownership.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/operations/evidence-ownership.md",
    ),
    (
        "canonicals/docs/operations/runbook_dev_tier.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/operations/runbook_dev_tier.md",
    ),
    (
        "canonicals/docs/operations/running-belgi.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/operations/running-belgi.md",
    ),
    (
        "canonicals/docs/operations/security.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/operations/security.md",
    ),
    (
        "canonicals/docs/operations/waivers.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/operations/waivers.md",
    ),
    ("canonicals/docs/research/README.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/research/README.md"),
    (
        "canonicals/docs/research/experiment-design.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/research/experiment-design.md",
    ),
    ("canonicals/docs/research/metrics.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/docs/research/metrics.md"),
)
_C3_CANONICAL_PROTOCOL_BINDINGS: tuple[tuple[str, str], ...] = (
    ("_protocol_packs/v1/gates/GATE_Q.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/gates/GATE_Q.md"),
    ("_protocol_packs/v1/gates/GATE_R.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/gates/GATE_R.md"),
    ("_protocol_packs/v1/gates/GATE_S.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/gates/GATE_S.md"),
    (
        "_protocol_packs/v1/gates/failure-taxonomy.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/gates/failure-taxonomy.md",
    ),
    ("_protocol_packs/v1/tiers/tier-packs.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/tiers/tier-packs.md"),
    (
        "_protocol_packs/v1/tiers/tier-packs.template.md",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/tiers/tier-packs.template.md",
    ),
    ("_protocol_packs/v1/schemas/README.md", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/README.md"),
    (
        "_protocol_packs/v1/schemas/DocsCompilationLogPayload.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/DocsCompilationLogPayload.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/EnvAttestationPayload.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/EnvAttestationPayload.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/EvidenceManifest.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/EvidenceManifest.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/GateVerdict.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/GateVerdict.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/GenesisSealPayload.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/GenesisSealPayload.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/HOTLApproval.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/HOTLApproval.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/IntentSpec.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/IntentSpec.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/LockedSpec.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/LockedSpec.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/PolicyReportPayload.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/PolicyReportPayload.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/ReplayInstructionsPayload.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/ReplayInstructionsPayload.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/SealManifest.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/SealManifest.schema.json",
    ),
    (
        "_protocol_packs/v1/schemas/TestReportPayload.schema.json",
        f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/TestReportPayload.schema.json",
    ),
    ("_protocol_packs/v1/schemas/Waiver.schema.json", f"{_C3_CANONICAL_STAGE_ROOT_REPO_REL}/schemas/Waiver.schema.json"),
)
_C3_CANONICAL_BINDINGS: tuple[tuple[str, str], ...] = _C3_CANONICAL_PACKAGE_BINDINGS + _C3_CANONICAL_PROTOCOL_BINDINGS


@dataclass(frozen=True)
class RunOrchestrationResult:
    chain_repo_dir: Path
    chain_out_dir: Path
    rel_evidence_final: str
    rel_seal: str
    rel_gate_s: str
    chain_paths: list[Path]
    adversarial_findings_count: int
    adversarial_findings_present: bool
    applied_waiver_refs: list[str]


@dataclass(frozen=True)
class TierTestPlan:
    mode: str
    test_path: str | None


def render_default_intent_spec(*, tier_id: str) -> bytes:
    text = (
        "# IntentSpec (auto-generated by belgi run)\n\n"
        "```yaml\n"
        'intent_id: "INTENT-AUTO-RUN"\n'
        'title: "Deterministic BELGI chain run"\n'
        'goal: "Execute the canonical BELGI chain to Seal deterministically."\n'
        "scope:\n"
        "  allowed_dirs:\n"
        '    - "belgi/"\n'
        "  forbidden_dirs:\n"
        '    - "main/"\n'
        "acceptance:\n"
        "  success_criteria:\n"
        '    - "Gate Q, Gate R, and Gate S return GO."\n'
        "tier:\n"
        f'  tier_pack_id: "{tier_id}"\n'
        "doc_impact:\n"
        "  required_paths: []\n"
        '  note_on_empty: "No documentation updates are required for this deterministic workspace run."\n'
        "publication_intent:\n"
        "  publish: true\n"
        '  profile: "public"\n'
        "```\n"
    )
    return text.encode("utf-8", errors="strict")


def _invoke_module_main(module_name: str, argv: list[str]) -> int:
    module = importlib.import_module(module_name)
    main_fn = getattr(module, "main", None)
    if not callable(main_fn):
        raise ValueError(f"{module_name} does not expose a callable main()")

    try:
        sig = inspect.signature(main_fn)
    except Exception:
        sig = None

    try:
        if sig is not None and len(sig.parameters) == 0:
            old_argv = sys.argv
            sys.argv = [module_name, *argv]
            try:
                rc = main_fn()
            finally:
                sys.argv = old_argv
        else:
            rc = main_fn(argv)
    except SystemExit as e:
        if isinstance(e.code, int):
            return e.code
        return 3

    if rc is None:
        return 0
    if not isinstance(rc, int):
        raise ValueError(f"{module_name} returned non-integer exit code: {rc!r}")
    return rc


def _run_module_expect_rc(module_name: str, argv: list[str], *, allowed: tuple[int, ...] = (0,)) -> None:
    rc = _invoke_module_main(module_name, argv)
    if rc not in allowed:
        raise ValueError(f"{module_name} returned rc={rc}")


def _run_tools_belgi(repo_root: Path, argv: list[str], *, allowed: tuple[int, ...] = (0,)) -> int:
    rc = _invoke_module_main("tools.belgi_tools", [*argv, "--repo", str(repo_root)])
    if rc not in allowed:
        raise ValueError(f"tools.belgi_tools {' '.join(argv)} returned rc={rc}")
    return rc


def _git_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
    if dest_repo.exists():
        raise ValueError(f"clone destination already exists: {dest_repo}")

    cp_clone = subprocess.run(
        ["git", "clone", "--quiet", "--shared", "--", str(source_repo), str(dest_repo)],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    if cp_clone.returncode != 0:
        msg = (cp_clone.stderr or cp_clone.stdout or "").strip()
        raise ValueError(f"git clone failed: {msg or 'unknown error'}")

    cp_checkout = subprocess.run(
        ["git", "-C", str(dest_repo), "checkout", "--quiet", commit_sha],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    if cp_checkout.returncode != 0:
        msg = (cp_checkout.stderr or cp_checkout.stdout or "").strip()
        raise ValueError(f"git checkout failed: {msg or 'unknown error'}")


def _git_diff_bytes(*, repo_root: Path, upstream: str, evaluated: str) -> bytes:
    cp = subprocess.run(
        [
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
        ],
        capture_output=True,
        check=False,
        shell=False,
    )
    if cp.returncode != 0:
        msg = cp.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git diff failed: {msg or f'rc={cp.returncode}'}")
    return cp.stdout


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _load_json_object(path: Path, *, label: str) -> dict[str, object]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception as e:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"{label} must be a JSON object")
    return obj


def _command_log_mode_for_tier(*, protocol: Any, tier_id: str) -> str:
    try:
        from chain.logic.tier_packs import load_tier_params
    except Exception as e:
        raise ValueError(f"tier parser unavailable for run orchestration: {e}") from e

    tiers_text = protocol.read_text("tiers/tier-packs.json")
    loaded = load_tier_params(tiers_text, tier_id)
    if loaded.params is None:
        parse_err = loaded.parse_error or "unknown parse failure"
        raise ValueError(f"tier parameter parse failed: {parse_err}")
    mode = loaded.params.command_log_mode
    if mode not in ("strings", "structured"):
        raise ValueError(f"unsupported command_log_mode for tier {tier_id}: {mode!r}")
    return str(mode)


def _tier_test_plan_for_tier(*, protocol: Any, tier_id: str) -> TierTestPlan:
    """Resolve deterministic test evidence producer plan from tier policy."""

    try:
        from chain.logic.tier_packs import load_tier_params
    except Exception as e:
        raise ValueError(f"tier parser unavailable for run orchestration: {e}") from e

    tiers_text = protocol.read_text("tiers/tier-packs.json")
    loaded = load_tier_params(tiers_text, tier_id)
    if loaded.params is None:
        parse_err = loaded.parse_error or "unknown parse failure"
        raise ValueError(f"tier parameter parse failed: {parse_err}")

    # Tier test evidence is driven by tier policy. Safe default is repo-agnostic.
    mode = "engine_smoke" if loaded.params.test_policy_required == "yes" else "engine_smoke"
    test_path: str | None = None

    try:
        tiers_obj = protocol.read_json("tiers/tier-packs.json")
    except Exception as e:
        raise ValueError(f"cannot parse tier-packs.json for test policy planning: {e}") from e
    if isinstance(tiers_obj, dict):
        tiers = tiers_obj.get("tiers")
        tier_obj = tiers.get(tier_id) if isinstance(tiers, dict) else None
        test_policy = tier_obj.get("test_policy") if isinstance(tier_obj, dict) else None
        if isinstance(test_policy, dict):
            raw_mode = test_policy.get("runner_mode")
            if raw_mode is not None:
                if not isinstance(raw_mode, str) or raw_mode not in ("engine_smoke", "adopter_pytest"):
                    raise ValueError(
                        f"tier test_policy.runner_mode missing/invalid for tier {tier_id}: {raw_mode!r}"
                    )
                mode = raw_mode

            raw_target = test_policy.get("target")
            if raw_target is not None:
                if not isinstance(raw_target, str) or not raw_target.strip():
                    raise ValueError(f"tier test_policy.target missing/invalid for tier {tier_id}")
                test_path = raw_target.strip()

    if mode == "adopter_pytest" and not test_path:
        test_path = "tests"
    if mode == "engine_smoke" and test_path is not None:
        raise ValueError(f"tier test_policy.target requires runner_mode=adopter_pytest for tier {tier_id}")

    return TierTestPlan(mode=mode, test_path=test_path)


def _append_command(
    *,
    commands_executed: list[Any],
    command_log_mode: str,
    subcommand: str,
    exit_code: int,
) -> list[Any]:
    return append_command_to_manifest(
        commands_executed,
        mode=command_log_mode,
        argv=["belgi", subcommand],
        exit_code=exit_code,
        timestamp=FIXED_GENERATED_AT,
    )


def _require_commit_sha40(value: str, *, label: str) -> str:
    sha = str(value or "").strip().lower()
    if not _SHA1_40_RE.fullmatch(sha):
        raise ValueError(f"{label} must be a stable 40-hex commit SHA")
    return sha


def _load_builtin_resource_bytes(*, resource_rel: str) -> bytes:
    try:
        node = resource_files("belgi").joinpath(*resource_rel.split("/"))
        return node.read_bytes()
    except Exception as e:
        raise ValueError(f"missing builtin BELGI resource: {resource_rel}") from e


def ensure_chain_templates(*, chain_repo_root: Path) -> None:
    for resource_rel, target_rel in _CHAIN_TEMPLATE_BINDINGS:
        builtin_bytes = _load_builtin_resource_bytes(resource_rel=resource_rel)
        target_path = chain_repo_root.joinpath(*target_rel.split("/"))
        if target_path.exists():
            if target_path.is_symlink() or not target_path.is_file():
                raise ValueError(
                    f"CHAIN_TEMPLATE_MISMATCH: {target_rel}; adopter overrides are not allowed; "
                    "delete file or match builtin."
                )
            current_bytes = target_path.read_bytes()
            if current_bytes != builtin_bytes:
                raise ValueError(
                    f"CHAIN_TEMPLATE_MISMATCH: {target_rel}; adopter overrides are not allowed; "
                    "delete file or match builtin."
                )
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(builtin_bytes)


def ensure_chain_c3_canonicals(*, chain_repo_root: Path) -> None:
    for resource_rel, target_rel in _C3_CANONICAL_BINDINGS:
        builtin_bytes = _load_builtin_resource_bytes(resource_rel=resource_rel)
        target_path = chain_repo_root.joinpath(*target_rel.split("/"))
        if target_path.exists():
            if target_path.is_symlink() or not target_path.is_file():
                raise ValueError(
                    f"CHAIN_CANONICAL_MISMATCH: {target_rel}; staged engine canonicals are immutable; "
                    "delete file or match builtin."
                )
            current_bytes = target_path.read_bytes()
            if current_bytes != builtin_bytes:
                raise ValueError(
                    f"CHAIN_CANONICAL_MISMATCH: {target_rel}; staged engine canonicals are immutable; "
                    "delete file or match builtin."
                )
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(builtin_bytes)


def _discover_applied_waiver_files(*, source_repo_root: Path) -> list[Path]:
    waivers_dir = source_repo_root.joinpath(*_APPLIED_WAIVERS_SOURCE_REPO_REL.split("/"))
    if not waivers_dir.exists():
        return []
    if waivers_dir.is_symlink() or not waivers_dir.is_dir():
        raise ValueError(f"invalid applied waivers directory: {_APPLIED_WAIVERS_SOURCE_REPO_REL}")

    waiver_files: list[Path] = []
    for child in sorted(waivers_dir.iterdir(), key=lambda p: p.name):
        if child.name.startswith("."):
            continue
        if child.is_symlink() or child.is_dir() or not child.is_file():
            raise ValueError(f"invalid waiver entry: {_APPLIED_WAIVERS_SOURCE_REPO_REL}/{child.name}")
        if child.suffix.lower() != ".json":
            continue
        waiver_files.append(child)
    return waiver_files


def stage_applied_waivers(*, source_repo_root: Path, chain_repo_root: Path) -> list[str]:
    source_files = _discover_applied_waiver_files(source_repo_root=source_repo_root)
    if not source_files:
        return []

    staged_dir = chain_repo_root.joinpath(*_APPLIED_WAIVERS_STAGE_REPO_REL.split("/"))
    staged_dir.mkdir(parents=True, exist_ok=True)

    staged_refs: list[str] = []
    seen_names: set[str] = set()
    for source_file in source_files:
        file_name = source_file.name
        if file_name in seen_names:
            raise ValueError(f"duplicate waiver filename: {file_name}")
        seen_names.add(file_name)
        target_file = staged_dir / file_name
        target_file.write_bytes(source_file.read_bytes())
        staged_refs.append(safe_relpath(chain_repo_root, target_file))

    staged_refs.sort()
    return staged_refs


def _parse_registry_block_ids(registry_text: str) -> list[str]:
    ids = sorted(set(re.findall(r"\bPB-\d{3}\b", registry_text)))
    if not ids:
        raise ValueError("prompt block registry contains no PB-* ids")
    return ids


def _render_prompt_block_bytes(*, block_id: str, locked_spec_preimage: dict[str, object]) -> bytes:
    c1_module = importlib.import_module("chain.compiler_c1_intent")
    render_fn = getattr(c1_module, "_render_prompt_block", None)
    if not callable(render_fn):
        raise ValueError("chain.compiler_c1_intent._render_prompt_block is unavailable")
    try:
        rendered = render_fn(block_id=block_id, locked_spec_preimage=locked_spec_preimage)
    except Exception as e:
        raise ValueError(f"cannot deterministically render prompt block {block_id}: {e}") from e
    if not isinstance(rendered, (bytes, bytearray)):
        raise ValueError(f"prompt block renderer returned non-bytes for {block_id}")
    return bytes(rendered)


def _ensure_complete_prompt_block_hashes(
    *,
    chain_repo_root: Path,
    prompt_hashes_path: Path,
    locked_spec: dict[str, object],
) -> None:
    mapping_obj = _load_json_object(prompt_hashes_path, label="prompt_block_hashes.json")
    mapping: dict[str, str] = {}
    for k, v in mapping_obj.items():
        if isinstance(k, str) and isinstance(v, str):
            if not _SHA256_RE.fullmatch(v):
                raise ValueError(f"invalid prompt block hash for {k}: expected 64-hex")
            mapping[k] = v.lower()

    registry_path = chain_repo_root / "belgi" / "templates" / "PromptBundle.blocks.md"
    if not registry_path.exists() or registry_path.is_symlink() or not registry_path.is_file():
        raise ValueError(f"missing prompt block registry: {registry_path}")
    registry_text = registry_path.read_text(encoding="utf-8", errors="strict")
    required_block_ids = _parse_registry_block_ids(registry_text)

    changed = False
    for block_id in required_block_ids:
        if block_id in mapping:
            continue
        rendered = _render_prompt_block_bytes(block_id=block_id, locked_spec_preimage=locked_spec)
        mapping[block_id] = sha256_bytes(rendered)
        changed = True

    if changed:
        ordered = {k: mapping[k] for k in sorted(mapping.keys())}
        _write_json(prompt_hashes_path, ordered)


def _raise_gate_failure(
    *,
    module_name: str,
    rc: int,
    chain_repo_root: Path,
    gate_verdict_rel: str,
) -> None:
    if rc == 2:
        verdict_path = chain_repo_root / gate_verdict_rel
        if verdict_path.exists() and not verdict_path.is_symlink() and verdict_path.is_file():
            verdict_obj = _load_json_object(verdict_path, label=f"{module_name} GateVerdict")
            failure_category = verdict_obj.get("failure_category")
            category = str(failure_category).strip() if isinstance(failure_category, str) else ""
            failures = verdict_obj.get("failures")
            if isinstance(failures, list) and len(failures) > 0 and isinstance(failures[0], dict):
                message = failures[0].get("message")
                if isinstance(message, str) and message.strip():
                    if category:
                        raise ValueError(f"{module_name} NO-GO: {category}: {message.strip()}")
                    raise ValueError(f"{module_name} NO-GO: {message.strip()}")
    raise ValueError(f"{module_name} returned rc={rc}")


def _make_evidence_artifact(
    *,
    chain_repo_root: Path,
    path: Path,
    kind: str,
    artifact_id: str,
    media_type: str,
    produced_by: str,
) -> dict[str, str]:
    return {
        "kind": kind,
        "id": artifact_id,
        "hash": sha256_bytes(path.read_bytes()),
        "media_type": media_type,
        "storage_ref": safe_relpath(chain_repo_root, path),
        "produced_by": produced_by,
    }


def _collect_chain_artifact_paths(*, chain_repo_root: Path, chain_out_dir: Path) -> list[Path]:
    if chain_out_dir.is_symlink() or not chain_out_dir.is_dir():
        raise ValueError(f"missing chain output directory: {chain_out_dir}")

    out_files: list[Path] = []
    for p in sorted(chain_out_dir.rglob("*"), key=lambda x: x.as_posix()):
        if p.is_symlink():
            raise ValueError(f"symlink output not allowed: {p}")
        if p.is_file():
            out_files.append(p)

    extras = [
        chain_repo_root / "IntentSpec.core.md",
        chain_repo_root / "docs" / "docs_compilation_log.json",
    ]
    for p in extras:
        if not p.exists() or p.is_symlink() or not p.is_file():
            raise ValueError(f"missing required chain artifact: {p}")
        out_files.append(p)

    dedup: dict[str, Path] = {}
    for p in out_files:
        dedup[str(p.resolve())] = p
    return sorted(dedup.values(), key=lambda x: x.as_posix())


def orchestrate_chain_run(
    *,
    source_repo_root: Path,
    chain_repo_dir: Path,
    run_key: str,
    tier_id: str,
    base_revision: str,
    evaluated_revision: str,
    revision_discovery_method: str,
    upstream_ref: str | None,
    intent_bytes: bytes,
    protocol: Any,
) -> RunOrchestrationResult:
    base_revision = _require_commit_sha40(base_revision, label="base_revision")
    evaluated_revision = _require_commit_sha40(evaluated_revision, label="evaluated_revision")
    if revision_discovery_method not in ("ci_env", "merge_base", "explicit"):
        raise ValueError(
            "revision_discovery_method must be one of: ci_env, merge_base, explicit"
        )

    command_log_mode = _command_log_mode_for_tier(protocol=protocol, tier_id=tier_id)
    tier_test_plan = _tier_test_plan_for_tier(protocol=protocol, tier_id=tier_id) if tier_id == "tier-1" else None

    chain_out_dir = chain_repo_dir / CHAIN_OUT_DIRNAME
    chain_artifacts_dir = chain_out_dir / "artifacts"

    rel_locked = f"{CHAIN_OUT_DIRNAME}/LockedSpec.json"
    rel_prompt_bundle = f"{CHAIN_OUT_DIRNAME}/prompt_bundle.md"
    rel_prompt_hashes = f"{CHAIN_OUT_DIRNAME}/prompt_block_hashes.json"
    rel_prompt_policy = f"{CHAIN_OUT_DIRNAME}/policy.prompt_bundle.json"
    rel_policy_inv = f"{CHAIN_OUT_DIRNAME}/artifacts/policy.invariant_eval.json"
    rel_policy_revision_binding = f"{CHAIN_OUT_DIRNAME}/artifacts/policy.revision_binding.json"
    rel_policy_supply = f"{CHAIN_OUT_DIRNAME}/artifacts/policy.supplychain.json"
    rel_policy_adv = f"{CHAIN_OUT_DIRNAME}/artifacts/policy.adversarial_scan.json"
    rel_command_log = f"{CHAIN_OUT_DIRNAME}/artifacts/command_log.json"
    rel_diff = f"{CHAIN_OUT_DIRNAME}/artifacts/diff.patch"
    rel_test_report = f"{CHAIN_OUT_DIRNAME}/artifacts/tests.report.json"
    rel_env_att = f"{CHAIN_OUT_DIRNAME}/artifacts/env.attestation.json"
    rel_evidence_input = f"{CHAIN_OUT_DIRNAME}/EvidenceManifest.input.json"
    rel_gate_q = f"{CHAIN_OUT_DIRNAME}/GateVerdict.Q.json"
    rel_verify_report = f"{CHAIN_OUT_DIRNAME}/verify_report.R.json"
    rel_gate_r = f"{CHAIN_OUT_DIRNAME}/GateVerdict.R.json"
    rel_r_snapshot = f"{CHAIN_OUT_DIRNAME}/EvidenceManifest.r_snapshot.json"
    rel_evidence_final = f"{CHAIN_OUT_DIRNAME}/EvidenceManifest.json"
    rel_docs = f"{CHAIN_OUT_DIRNAME}/run_docs.md"
    rel_bundle = f"{CHAIN_OUT_DIRNAME}/bundle"
    rel_bundle_root_sha = f"{CHAIN_OUT_DIRNAME}/bundle_root.sha256"
    rel_seal = f"{CHAIN_OUT_DIRNAME}/SealManifest.json"
    rel_gate_s = f"{CHAIN_OUT_DIRNAME}/GateVerdict.S.json"

    _git_clone_at_commit(source_repo=source_repo_root, dest_repo=chain_repo_dir, commit_sha=evaluated_revision)

    commands_executed: list[Any] = []
    rc_supply = run_supplychain_scan(
        repo=chain_repo_dir,
        evaluated_revision=evaluated_revision,
        out_path=chain_repo_dir / rel_policy_supply,
        deterministic=True,
        run_id=run_key,
    )
    if rc_supply != 0:
        raise ValueError(f"supplychain scan failed (rc={rc_supply})")
    commands_executed = _append_command(
        commands_executed=commands_executed,
        command_log_mode=command_log_mode,
        subcommand="supplychain-scan",
        exit_code=rc_supply,
    )

    ensure_chain_templates(chain_repo_root=chain_repo_dir)
    ensure_chain_c3_canonicals(chain_repo_root=chain_repo_dir)

    chain_out_dir.mkdir(parents=True, exist_ok=True)
    chain_artifacts_dir.mkdir(parents=True, exist_ok=True)
    applied_waiver_refs = stage_applied_waivers(
        source_repo_root=source_repo_root,
        chain_repo_root=chain_repo_dir,
    )

    intent_in_chain = chain_repo_dir / "IntentSpec.core.md"
    intent_in_chain.write_bytes(intent_bytes)

    tolerances_path = chain_out_dir / "inputs" / "tolerances.json"
    toolchain_path = chain_out_dir / "inputs" / "toolchain.json"
    _write_json(tolerances_path, {"schema_version": "1.0.0", "tier_id": tier_id})
    _write_json(
        toolchain_path,
        {
            "schema_version": "1.0.0",
            "python_version": sys.version.split()[0],
            "runner": "belgi.cli.run",
        },
    )

    repo_ref = str(upstream_ref).strip() if isinstance(upstream_ref, str) and str(upstream_ref).strip() else "HEAD"
    c1_argv = [
        "--repo",
        str(chain_repo_dir),
        "--intent-spec",
        "IntentSpec.core.md",
        "--out",
        rel_locked,
        "--run-id",
        run_key,
        "--repo-ref",
        repo_ref,
        "--upstream-commit-sha",
        base_revision,
        "--prompt-bundle-out",
        rel_prompt_bundle,
        "--prompt-bundle-id",
        "prompt.bundle",
        "--prompt-block-hashes-out",
        rel_prompt_hashes,
        "--prompt-bundle-policy-out",
        rel_prompt_policy,
        "--tolerances",
        f"tier.tolerances={safe_relpath(chain_repo_dir, tolerances_path)}",
        "--envelope-id",
        "env.default",
        "--envelope-description",
        "Deterministic BELGI run envelope",
        "--expected-runner",
        "belgi.cli.run",
        "--toolchain-ref",
        f"toolchain.main={safe_relpath(chain_repo_dir, toolchain_path)}",
    ]
    for waiver_ref in applied_waiver_refs:
        c1_argv.extend(["--waiver-applied", waiver_ref])

    ci_prev = os.environ.pop("CI", None)
    try:
        _run_module_expect_rc("chain.compiler_c1_intent", c1_argv)
    finally:
        if ci_prev is not None:
            os.environ["CI"] = ci_prev

    locked_spec_path = chain_repo_dir / rel_locked
    locked_spec = _load_json_object(locked_spec_path, label="LockedSpec.json")
    if str(locked_spec.get("run_id") or "") != run_key:
        raise ValueError("LockedSpec.run_id mismatch after C1 compilation")
    tier_obj = locked_spec.get("tier")
    locked_tier = str(tier_obj.get("tier_id") or "") if isinstance(tier_obj, dict) else ""
    if locked_tier != tier_id:
        raise ValueError(f"LockedSpec tier mismatch: expected {tier_id}, got {locked_tier or '<missing>'}")
    upstream_state = locked_spec.get("upstream_state")
    locked_base_revision = (
        str(upstream_state.get("commit_sha") or "")
        if isinstance(upstream_state, dict)
        else ""
    )
    if locked_base_revision != base_revision:
        raise ValueError(
            "LockedSpec.upstream_state.commit_sha mismatch after C1 compilation "
            f"(expected {base_revision}, got {locked_base_revision or '<missing>'})"
        )

    _ensure_complete_prompt_block_hashes(
        chain_repo_root=chain_repo_dir,
        prompt_hashes_path=chain_repo_dir / rel_prompt_hashes,
        locked_spec=locked_spec,
    )

    rc_inv = _run_tools_belgi(
        chain_repo_dir,
        ["invariant-eval", "--locked-spec", rel_locked, "--out", rel_policy_inv, "--deterministic"],
        allowed=(0,),
    )
    commands_executed = _append_command(
        commands_executed=commands_executed,
        command_log_mode=command_log_mode,
        subcommand="invariant-eval",
        exit_code=rc_inv,
    )

    rc_adv = run_adversarial_scan(
        repo=chain_repo_dir,
        out_path=chain_repo_dir / rel_policy_adv,
        deterministic=True,
        run_id=run_key,
    )
    if rc_adv not in (0, 2):
        raise ValueError(f"adversarial scan failed (rc={rc_adv})")
    adv_policy_obj = _load_json_object(chain_repo_dir / rel_policy_adv, label="policy.adversarial_scan.json")
    findings_count_raw = adv_policy_obj.get("finding_count")
    if not isinstance(findings_count_raw, int) or isinstance(findings_count_raw, bool) or findings_count_raw < 0:
        raise ValueError("policy.adversarial_scan finding_count missing/invalid")
    findings_present_raw = adv_policy_obj.get("findings_present")
    if findings_present_raw is None:
        findings_present = findings_count_raw > 0
    elif isinstance(findings_present_raw, bool):
        findings_present = findings_present_raw
    else:
        raise ValueError("policy.adversarial_scan findings_present missing/invalid")
    if findings_present != (findings_count_raw > 0):
        raise ValueError("policy.adversarial_scan findings_present inconsistent with finding_count")
    commands_executed = _append_command(
        commands_executed=commands_executed,
        command_log_mode=command_log_mode,
        subcommand="adversarial-scan",
        exit_code=rc_adv,
    )

    diff_path = chain_repo_dir / rel_diff
    diff_path.parent.mkdir(parents=True, exist_ok=True)
    diff_path.write_bytes(
        _git_diff_bytes(repo_root=chain_repo_dir, upstream=base_revision, evaluated=evaluated_revision)
    )

    command_log_path = chain_repo_dir / rel_command_log
    test_report_path = chain_repo_dir / rel_test_report
    env_att_path = chain_repo_dir / rel_env_att

    envelope_attestation: dict[str, str] | None = None
    if tier_id == "tier-1":
        if tier_test_plan is None:
            raise ValueError("internal error: missing tier test plan for tier-1")
        if tier_test_plan.mode not in ("engine_smoke", "adopter_pytest"):
            raise ValueError(f"unsupported tier test runner mode: {tier_test_plan.mode!r}")
        run_tests_argv = [
            "run-tests",
            "--run-id",
            run_key,
            "--out",
            rel_test_report,
            "--deterministic",
        ]
        if tier_test_plan.mode == "adopter_pytest":
            if not isinstance(tier_test_plan.test_path, str) or not tier_test_plan.test_path:
                raise ValueError("tier test runner mode adopter_pytest requires a configured test target")
            run_tests_argv.extend(["--test-path", tier_test_plan.test_path])

        rc_tests = _run_tools_belgi(
            chain_repo_dir,
            run_tests_argv,
            allowed=(0,),
        )
        commands_executed = _append_command(
            commands_executed=commands_executed,
            command_log_mode=command_log_mode,
            subcommand="run-tests",
            exit_code=rc_tests,
        )

        commands_with_att = _append_command(
            commands_executed=commands_executed,
            command_log_mode=command_log_mode,
            subcommand="verify-attestation",
            exit_code=0,
        )
        _write_json(
            command_log_path,
            {"schema_version": "1.0.0", "run_id": run_key, "commands_executed": commands_with_att},
        )

        rc_att = _run_tools_belgi(
            chain_repo_dir,
            [
                "verify-attestation",
                "--run-id",
                run_key,
                "--command-log",
                rel_command_log,
                "--locked-spec",
                rel_locked,
                "--out",
                rel_env_att,
                "--deterministic",
            ],
            allowed=(0,),
        )
        commands_executed = _append_command(
            commands_executed=commands_executed,
            command_log_mode=command_log_mode,
            subcommand="verify-attestation",
            exit_code=rc_att,
        )
        _write_json(
            command_log_path,
            {"schema_version": "1.0.0", "run_id": run_key, "commands_executed": commands_executed},
        )

        envelope_attestation = {
            "id": "env.attestation",
            "hash": sha256_bytes(env_att_path.read_bytes()),
            "storage_ref": safe_relpath(chain_repo_dir, env_att_path),
        }
    else:
        _write_json(
            command_log_path,
            {"schema_version": "1.0.0", "run_id": run_key, "commands_executed": commands_executed},
        )

    revision_binding_payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "run_id": run_key,
        "generated_at": FIXED_GENERATED_AT,
        "summary": {"total_checks": 1, "passed": 1, "failed": 0},
        "checks": [
            {
                "check_id": "REV-BIND-001",
                "passed": True,
                "message": "base and evaluated revisions are bound into the run contract.",
                "base_revision": base_revision,
                "evaluated_revision": evaluated_revision,
                "discovery_method": revision_discovery_method,
                "upstream_ref": repo_ref if upstream_ref is not None else None,
            }
        ],
        "base_revision": base_revision,
        "evaluated_revision": evaluated_revision,
        "discovery_method": revision_discovery_method,
    }
    revision_binding_path = chain_repo_dir / rel_policy_revision_binding
    revision_binding_schema = protocol.read_json("schemas/PolicyReportPayload.schema.json")
    if not isinstance(revision_binding_schema, dict):
        raise ValueError("PolicyReportPayload schema must be a JSON object")
    revision_binding_errors = validate_schema(
        revision_binding_payload,
        revision_binding_schema,
        root_schema=revision_binding_schema,
        path="PolicyReportPayload",
    )
    if revision_binding_errors:
        first = revision_binding_errors[0]
        raise ValueError(f"revision binding policy payload invalid at {first.path}: {first.message}")
    _write_json(revision_binding_path, revision_binding_payload)

    artifacts = [
        _make_evidence_artifact(
            chain_repo_root=chain_repo_dir,
            path=locked_spec_path,
            kind="schema_validation",
            artifact_id="schema.lockedspec",
            media_type="application/json",
            produced_by="C1",
        ),
        _make_evidence_artifact(
            chain_repo_root=chain_repo_dir,
            path=command_log_path,
            kind="command_log",
            artifact_id="command.log",
            media_type="application/json",
            produced_by="C1",
        ),
        _make_evidence_artifact(
            chain_repo_root=chain_repo_dir,
            path=chain_repo_dir / rel_policy_inv,
            kind="policy_report",
            artifact_id="policy.invariant_eval",
            media_type="application/json",
            produced_by="C1",
        ),
        _make_evidence_artifact(
            chain_repo_root=chain_repo_dir,
            path=revision_binding_path,
            kind="policy_report",
            artifact_id="policy.revision_binding",
            media_type="application/json",
            produced_by="C1",
        ),
        _make_evidence_artifact(
            chain_repo_root=chain_repo_dir,
            path=chain_repo_dir / rel_policy_supply,
            kind="policy_report",
            artifact_id="policy.supplychain",
            media_type="application/json",
            produced_by="C1",
        ),
        _make_evidence_artifact(
            chain_repo_root=chain_repo_dir,
            path=chain_repo_dir / rel_policy_adv,
            kind="policy_report",
            artifact_id="policy.adversarial_scan",
            media_type="application/json",
            produced_by="C1",
        ),
        _make_evidence_artifact(
            chain_repo_root=chain_repo_dir,
            path=diff_path,
            kind="diff",
            artifact_id="changes.diff",
            media_type="text/x-diff",
            produced_by="C1",
        ),
    ]

    if tier_id == "tier-1":
        artifacts.append(
            _make_evidence_artifact(
                chain_repo_root=chain_repo_dir,
                path=test_report_path,
                kind="test_report",
                artifact_id="tests.report",
                media_type="application/json",
                produced_by="C1",
            )
        )
        artifacts.append(
            _make_evidence_artifact(
                chain_repo_root=chain_repo_dir,
                path=env_att_path,
                kind="env_attestation",
                artifact_id="env.attestation",
                media_type="application/json",
                produced_by="C1",
            )
        )
    artifacts.sort(key=lambda a: (a.get("kind", ""), a.get("id", ""), a.get("storage_ref", "")))

    evidence_input = {
        "schema_version": "1.0.0",
        "run_id": run_key,
        "artifacts": artifacts,
        "commands_executed": commands_executed,
        "envelope_attestation": envelope_attestation,
    }
    evidence_schema = protocol.read_json("schemas/EvidenceManifest.schema.json")
    if not isinstance(evidence_schema, dict):
        raise ValueError("EvidenceManifest schema must be a JSON object")
    em_errors = validate_schema(
        evidence_input,
        evidence_schema,
        root_schema=evidence_schema,
        path="EvidenceManifest",
    )
    if em_errors:
        first = em_errors[0]
        raise ValueError(f"initial EvidenceManifest invalid at {first.path}: {first.message}")
    _write_json(chain_repo_dir / rel_evidence_input, evidence_input)

    gate_q_argv = [
        "--repo",
        str(chain_repo_dir),
        "--intent-spec",
        "IntentSpec.core.md",
        "--locked-spec",
        rel_locked,
        "--evidence-manifest",
        rel_evidence_input,
        "--out",
        rel_gate_q,
    ]
    rc_gate_q = _invoke_module_main("chain.gate_q_verify", gate_q_argv)
    if rc_gate_q != 0:
        _raise_gate_failure(
            module_name="chain.gate_q_verify",
            rc=rc_gate_q,
            chain_repo_root=chain_repo_dir,
            gate_verdict_rel=rel_gate_q,
        )

    gate_r_argv = [
        "--repo",
        str(chain_repo_dir),
        "--locked-spec",
        rel_locked,
        "--gate-q-verdict",
        rel_gate_q,
        "--evidence-manifest",
        rel_evidence_input,
        "--r-snapshot-manifest-out",
        rel_r_snapshot,
        "--gate-verdict-out",
        rel_gate_r,
        "--out",
        rel_verify_report,
        "--evaluated-revision",
        evaluated_revision,
    ]
    rc_gate_r = _invoke_module_main("chain.gate_r_verify", gate_r_argv)
    if rc_gate_r != 0:
        _raise_gate_failure(
            module_name="chain.gate_r_verify",
            rc=rc_gate_r,
            chain_repo_root=chain_repo_dir,
            gate_verdict_rel=rel_gate_r,
        )

    profile = "public"
    pub_intent = locked_spec.get("publication_intent")
    if isinstance(pub_intent, dict):
        prof = pub_intent.get("profile")
        if isinstance(prof, str) and prof in ("public", "internal"):
            profile = prof

    _run_module_expect_rc(
        "chain.compiler_c3_docs",
        [
            "--repo",
            str(chain_repo_dir),
            "--locked-spec",
            rel_locked,
            "--gate-q-verdict",
            rel_gate_q,
            "--gate-r-verdict",
            rel_gate_r,
            "--r-snapshot-manifest",
            rel_r_snapshot,
            "--out-final-manifest",
            rel_evidence_final,
            "--out-log",
            "docs/docs_compilation_log.json",
            "--out-docs",
            rel_docs,
            "--out-bundle-dir",
            rel_bundle,
            "--out-bundle-root-sha",
            rel_bundle_root_sha,
            "--profile",
            profile,
            "--prompt-block-hashes",
            rel_prompt_hashes,
        ],
    )

    seal_argv = [
        "--repo",
        str(chain_repo_dir),
        "--locked-spec",
        rel_locked,
        "--gate-q-verdict",
        rel_gate_q,
        "--gate-r-verdict",
        rel_gate_r,
        "--evidence-manifest",
        rel_evidence_final,
        "--final-commit-sha",
        evaluated_revision,
        "--sealed-at",
        FIXED_SEALED_AT,
        "--signer",
        FIXED_SIGNER,
        "--out",
        rel_seal,
    ]
    for waiver_ref in applied_waiver_refs:
        seal_argv.extend(["--waiver", waiver_ref])

    _run_module_expect_rc(
        "chain.seal_bundle",
        seal_argv,
    )

    _run_module_expect_rc(
        "chain.gate_s_verify",
        [
            "--repo",
            str(chain_repo_dir),
            "--locked-spec",
            rel_locked,
            "--seal-manifest",
            rel_seal,
            "--evidence-manifest",
            rel_evidence_final,
            "--out",
            rel_gate_s,
        ],
    )

    for src_rel, dst_rel in (
        (rel_gate_q, f"{CHAIN_OUT_DIRNAME}/GateVerdict_Q.json"),
        (rel_gate_r, f"{CHAIN_OUT_DIRNAME}/GateVerdict_R.json"),
        (rel_gate_s, f"{CHAIN_OUT_DIRNAME}/GateVerdict_S.json"),
    ):
        src = chain_repo_dir / src_rel
        dst = chain_repo_dir / dst_rel
        if not src.exists() or src.is_symlink() or not src.is_file():
            raise ValueError(f"missing GateVerdict output for bundle check alias: {src}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())

    chain_paths = _collect_chain_artifact_paths(chain_repo_root=chain_repo_dir, chain_out_dir=chain_out_dir)
    return RunOrchestrationResult(
        chain_repo_dir=chain_repo_dir,
        chain_out_dir=chain_out_dir,
        rel_evidence_final=rel_evidence_final,
        rel_seal=rel_seal,
        rel_gate_s=rel_gate_s,
        chain_paths=chain_paths,
        adversarial_findings_count=findings_count_raw,
        adversarial_findings_present=findings_present,
        applied_waiver_refs=applied_waiver_refs,
    )
