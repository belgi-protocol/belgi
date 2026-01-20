#!/usr/bin/env python3
"""Generic render tool for JSON canonical → Markdown generated view.

This tool implements the SSOT pattern: JSON files are canonical, MD files are
generated views via TEMPLATE SUBSTITUTION. Each render target loads a template
and replaces {{PLACEHOLDER}} markers with data-driven content.

CRITICAL: Renderers MUST NOT construct prose. They ONLY substitute placeholders.
All prose lives in the template file and is preserved byte-for-byte.

Exit codes:
  0 — OK (rendered successfully or --check passed)
  1 — Drift detected (--check mode only)
  2 — Usage/configuration error
  3 — Unexpected exception
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from belgi.core.jail import normalize_repo_rel as _normalize_repo_rel
from belgi.core.jail import resolve_repo_rel_path as _resolve_repo_rel_path


# ---------------------------------------------------------------------------
# Generic utilities
# ---------------------------------------------------------------------------


def load_canonical_json(repo_root: Path, relpath: str) -> Dict[str, Any]:
    """Load canonical JSON from a repo-relative path. Fail-closed on errors."""
    rel_posix = _normalize_repo_rel(relpath, allow_backslashes=True)
    path = _resolve_repo_rel_path(
        repo_root,
        rel_posix,
        must_exist=True,
        must_be_file=True,
        allow_backslashes=False,
        forbid_symlinks=True,
    )
    with path.open("r", encoding="utf-8", errors="strict") as f:
        return json.load(f)


def load_template(repo_root: Path, relpath: str) -> str:
    """Load template file from a repo-relative path. Fail-closed on errors."""
    rel_posix = _normalize_repo_rel(relpath, allow_backslashes=True)
    path = _resolve_repo_rel_path(
        repo_root,
        rel_posix,
        must_exist=True,
        must_be_file=True,
        allow_backslashes=False,
        forbid_symlinks=True,
    )
    with path.open("r", encoding="utf-8", errors="strict") as f:
        return f.read()


def render_by_substitution(template: str, mapping: Dict[str, str]) -> str:
    """Replace all {{PLACEHOLDER}} in template with values from mapping.
    
    Fail-closed:
    - Raises ValueError if template contains placeholders not in mapping.
    - Raises ValueError if mapping contains keys not used in template.
    """
    placeholder_pattern = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
    found_placeholders = set(placeholder_pattern.findall(template))
    
    # Fail-closed: template has placeholders not in mapping
    missing = found_placeholders - set(mapping.keys())
    if missing:
        raise ValueError(f"Template has unmapped placeholders: {sorted(missing)}")
    
    # Fail-closed: mapping has keys not used in template
    unused = set(mapping.keys()) - found_placeholders
    if unused:
        raise ValueError(f"Mapping has unused keys (not in template): {sorted(unused)}")
    
    result = template
    for key, value in mapping.items():
        placeholder = "{{" + key + "}}"
        result = result.replace(placeholder, value)
    
    return result


def ensure_no_remaining_placeholders(text: str) -> None:
    """Fail-closed if any {{...}} placeholders remain in text."""
    placeholder_pattern = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
    remaining = placeholder_pattern.findall(text)
    if remaining:
        raise ValueError(f"Unreplaced placeholders remain: {sorted(set(remaining))}")


def normalize_for_compare(text: str) -> str:
    """Normalize text for drift comparison.
    
    Normalization policy (explicit):
    1. CRLF → LF (newline style)
    2. Strip trailing whitespace per line
    3. Ensure exactly one trailing newline at EOF
    
    Does NOT normalize: punctuation, backticks, spacing within lines.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = [line.rstrip() for line in lines]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n" if lines else ""


def write_generated_md(path: Path, text: str) -> None:
    """Atomic write with Unix newlines for determinism."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.endswith("\n"):
        text += "\n"
    
    tmp = path.with_name(path.name + ".tmp.render")
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


# ---------------------------------------------------------------------------
# Render target registry
# ---------------------------------------------------------------------------


@dataclass
class RenderTarget:
    """A registered render target (template-based)."""
    name: str
    canonical_json: str       # repo-relative path to JSON SSOT
    template_file: str        # repo-relative path to template
    default_output: str       # repo-relative path to generated output
    compute_mapping: Callable[[Path, Dict[str, Any]], Dict[str, str]]  # (repo_root, data) → mapping
    description: str


RENDER_REGISTRY: Dict[str, RenderTarget] = {}


def register_target(target: RenderTarget) -> None:
    """Register a render target."""
    RENDER_REGISTRY[target.name] = target


# ---------------------------------------------------------------------------
# tier-packs: placeholder computation
# ---------------------------------------------------------------------------


def _fmt_bool_yesno(val: bool) -> str:
    """Format boolean as yes/no."""
    return "yes" if val else "no"


def _fmt_json_inline(items: List[str]) -> str:
    """Format list as inline JSON array."""
    return json.dumps(items, ensure_ascii=False)


def _compute_tier_ids_list(data: Dict[str, Any]) -> str:
    """Compute {{TP_TIER_IDS_LIST}} content."""
    tier_ids = data.get("tier_ids", [])
    lines = []
    for i, tid in enumerate(tier_ids):
        lines.append(f"- Tier {i}: `{tid}`")
    return "\n".join(lines)


def _compute_doc_impact_policy_map_table(data: Dict[str, Any]) -> str:
    """Compute {{TP_DOC_IMPACT_POLICY_MAP_TABLE}} content."""
    dipm = data.get("doc_impact_policy_map", {})
    lines = []
    lines.append("| tier_id | doc_impact required? | required_paths may be empty []? | note_on_empty required when empty []? | enforcing gate(s) |")
    lines.append("|---|---|---|---|---|")
    for t in dipm.get("tiers", []):
        dir_str = "yes" if t.get("doc_impact_required") else "no"
        rpe = "yes" if t.get("required_paths_may_be_empty") else "no"
        noe = t.get("note_on_empty_required_when_empty", "")
        gates = " ".join(t.get("enforcing_gates", []))
        lines.append(f"| {t['tier_id']} | {dir_str} | {rpe} | {noe} | {gates} |")
    return "\n".join(lines)


def _compute_tier_params(data: Dict[str, Any], tier_id: str) -> str:
    """Compute tier parameter block for a specific tier."""
    tiers = data.get("tiers", {})
    if tier_id not in tiers:
        raise ValueError(f"Tier {tier_id} not found in JSON")
    
    t = tiers[tier_id]
    lines = []
    
    lines.append(f"- required_evidence_kinds: `{_fmt_json_inline(t.get('required_evidence_kinds', []))}`")
    lines.append(f"- required_evidence_kinds_q: `{_fmt_json_inline(t.get('required_evidence_kinds_q', []))}`")
    lines.append(f"- command_log_mode: `\"{t.get('command_log_mode', '')}\"`")
    lines.append(f"- doc_impact_required: `{str(t.get('doc_impact_required', False)).lower()}`")
    
    tp = t.get("test_policy", {})
    lines.append("- test_policy:")
    lines.append(f"  - required: `{_fmt_bool_yesno(tp.get('required', False))}`")
    
    skips_base = _fmt_bool_yesno(tp.get("allowed_skips", False))
    if tp.get("allowed_skips_note"):
        lines.append(f"  - allowed_skips: `{skips_base}` ({tp['allowed_skips_note']})")
    else:
        lines.append(f"  - allowed_skips: `{skips_base}`")
    lines.append(f"  - flaky_handling: `{tp.get('flaky_handling', '')}`")
    
    sb = t.get("scope_budgets", {})
    lines.append("- scope_budgets:")
    lines.append(f"  - max_touched_files: `{sb.get('max_touched_files', 'null')}`")
    lines.append(f"  - max_loc_delta: `{sb.get('max_loc_delta', 'null')}`")
    lines.append(f"  - forbidden_paths_enforcement: `{sb.get('forbidden_paths_enforcement', 'strict')}`")
    
    wp = t.get("waiver_policy", {})
    lines.append("- waiver_policy:")
    lines.append(f"  - allowed: `{_fmt_bool_yesno(wp.get('allowed', False))}`")
    lines.append(f"  - max_active_waivers: `{wp.get('max_active_waivers', 0)}`")
    lines.append(f"  - requires_HOTL: `{_fmt_bool_yesno(wp.get('requires_HOTL', False))}`")
    
    ep = t.get("envelope_policy", {})
    lines.append("- envelope_policy:")
    lines.append(f"  - requires_attestation: `{_fmt_bool_yesno(ep.get('requires_attestation', False))}`")
    lines.append(f"  - attestation_signature_required: `{_fmt_bool_yesno(ep.get('attestation_signature_required', False))}`")
    lines.append(f"  - pinned_toolchain_refs_required: `{_fmt_bool_yesno(ep.get('pinned_toolchain_refs_required', True))}`")
    
    return "\n".join(lines)


def _compute_gate_parameter_map_table_prefix(data: Dict[str, Any]) -> str:
    """Compute {{TP_GATE_PARAMETER_MAP_TABLE_PREFIX}} content.
    
    Returns header + separator + all rows BEFORE R8 (Q1..R7).
    R8 is a literal row in template (prose lives in template, not renderer).
    """
    lines = []
    lines.append("| gate_check_id | tier params read |")
    lines.append("|---|---|")
    for entry in data.get("gate_parameter_map", []):
        gid = entry.get("gate_check_id", "")
        # Stop before R8 - R8 is literal in template
        if gid == "R8":
            break
        params = entry.get("tier_params_read", [])
        params_str = ", ".join(params) if params else "(none)"
        lines.append(f"| {gid} | {params_str} |")
    return "\n".join(lines)


def _compute_gate_parameter_map_table_suffix(data: Dict[str, Any]) -> str:
    """Compute {{TP_GATE_PARAMETER_MAP_TABLE_SUFFIX}} content.
    
    Returns all rows AFTER R8 (R-DOC-001 and beyond).
    """
    lines = []
    found_r8 = False
    for entry in data.get("gate_parameter_map", []):
        gid = entry.get("gate_check_id", "")
        if gid == "R8":
            found_r8 = True
            continue  # Skip R8, it's literal in template
        if not found_r8:
            continue  # Skip everything before R8
        params = entry.get("tier_params_read", [])
        params_str = ", ".join(params) if params else "(none)"
        lines.append(f"| {gid} | {params_str} |")
    return "\n".join(lines)


def compute_tier_packs_mapping(repo_root: Path, data: Dict[str, Any]) -> Dict[str, str]:
    """Compute all placeholder mappings for tier-packs template."""
    gate_parameter_map = data.get("gate_parameter_map", [])
    if not isinstance(gate_parameter_map, list):
        raise ValueError("tier-packs: gate_parameter_map must be a list")

    r8_count = sum(
        1
        for entry in gate_parameter_map
        if isinstance(entry, dict) and entry.get("gate_check_id") == "R8"
    )
    if r8_count != 1:
        raise ValueError(
            "tier-packs: gate_parameter_map must contain gate_check_id == 'R8' exactly once "
            f"(found {r8_count})"
        )

    return {
        "TP_TIER_IDS_LIST": _compute_tier_ids_list(data),
        "TP_DOC_IMPACT_POLICY_MAP_TABLE": _compute_doc_impact_policy_map_table(data),
        "TP_TIER_0_PARAMS": _compute_tier_params(data, "tier-0"),
        "TP_TIER_1_PARAMS": _compute_tier_params(data, "tier-1"),
        "TP_TIER_2_PARAMS": _compute_tier_params(data, "tier-2"),
        "TP_TIER_3_PARAMS": _compute_tier_params(data, "tier-3"),
        "TP_GATE_PARAMETER_MAP_TABLE_PREFIX": _compute_gate_parameter_map_table_prefix(data),
        "TP_GATE_PARAMETER_MAP_TABLE_SUFFIX": _compute_gate_parameter_map_table_suffix(data),
    }


# Register tier-packs target
register_target(RenderTarget(
    name="tier-packs",
    canonical_json="tiers/tier-packs.json",
    template_file="tiers/tier-packs.template.md",
    default_output="tiers/tier-packs.md",
    compute_mapping=compute_tier_packs_mapping,
    description="Tier parameter packs (policy bundles for gate enforcement)",
))


# ---------------------------------------------------------------------------
# Render engine
# ---------------------------------------------------------------------------


def render_target_to_string(repo_root: Path, target_name: str) -> str:
    """Render a target to string. Fails if target unknown or substitution fails."""
    if target_name not in RENDER_REGISTRY:
        raise ValueError(f"Unknown render target: {target_name}")
    
    target = RENDER_REGISTRY[target_name]
    
    data = load_canonical_json(repo_root, target.canonical_json)
    template = load_template(repo_root, target.template_file)
    
    mapping = target.compute_mapping(repo_root, data)
    result = render_by_substitution(template, mapping)
    
    ensure_no_remaining_placeholders(result)
    
    return result


def check_target_drift(repo_root: Path, target_name: str) -> tuple[bool, str]:
    """Check if a render target has drifted.
    
    Returns:
        (has_drift, message)
        has_drift: True if actual != expected (after normalization)
        message: Human-readable status message
    """
    if target_name not in RENDER_REGISTRY:
        return True, f"Unknown render target: {target_name}"
    
    target = RENDER_REGISTRY[target_name]
    
    try:
        expected = render_target_to_string(repo_root, target_name)
    except Exception as e:
        return True, f"Failed to render {target_name}: {e}"
    
    output_path = _resolve_repo_rel_path(
        repo_root,
        _normalize_repo_rel(target.default_output, allow_backslashes=True),
        must_exist=False,
        allow_backslashes=False,
        forbid_symlinks=True,
    )
    
    if not output_path.exists():
        return True, f"Output file does not exist: {target.default_output}"
    
    try:
        actual = output_path.read_text(encoding="utf-8", errors="strict")
    except Exception as e:
        return True, f"Failed to read {target.default_output}: {e}"
    
    expected_norm = normalize_for_compare(expected)
    actual_norm = normalize_for_compare(actual)
    
    if expected_norm != actual_norm:
        return True, f"Drift detected in {target.default_output}. Regenerate: python -m tools.render {target_name} --repo ."
    
    return False, f"No drift: {target.default_output}"


def get_all_target_names() -> List[str]:
    """Return sorted list of all registered target names."""
    return sorted(RENDER_REGISTRY.keys())


def get_target_evidence_files(target_name: str) -> List[str]:
    """Return list of evidence files for a target (for sweep reporting)."""
    if target_name not in RENDER_REGISTRY:
        return []
    target = RENDER_REGISTRY[target_name]
    return [
        "tools/render.py",
        target.canonical_json,
        target.template_file,
        target.default_output,
    ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: List[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="python -m tools.render",
        description="Render JSON canonical → Markdown generated view (template-based)",
    )
    ap.add_argument(
        "target",
        choices=list(RENDER_REGISTRY.keys()),
        help="Render target name",
    )
    ap.add_argument(
        "--repo",
        default=".",
        help="Repository root path (default: current directory)",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Output path (default: target's default_output)",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Check mode: verify no drift, do not write (exit 1 if drift)",
    )
    return ap.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    """Main entrypoint. Returns exit code."""
    try:
        args = _parse_args(argv)
        
        repo_root = Path(args.repo).resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            print(f"ERROR: repo root is not a directory: {repo_root}", file=sys.stderr)
            return 2
        
        target = RENDER_REGISTRY[args.target]
        
        if args.check:
            has_drift, msg = check_target_drift(repo_root, args.target)
            print(msg)
            return 1 if has_drift else 0
        
        rendered = render_target_to_string(repo_root, args.target)
        
        out_rel = args.out if args.out else target.default_output
        out_path = _resolve_repo_rel_path(
            repo_root,
            _normalize_repo_rel(out_rel, allow_backslashes=True),
            must_exist=False,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        
        out_path.parent.mkdir(parents=True, exist_ok=True)
        write_generated_md(out_path, rendered)
        
        print(f"Rendered: {out_rel}")
        return 0
        
    except json.JSONDecodeError as e:
        print(f"ERROR: JSON parse error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
