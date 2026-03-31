from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable

from tests.helpers import builders

REPO_ROOT = Path(__file__).resolve().parents[2]

FAMILY_PATH_PATTERNS: dict[str, tuple[str, ...]] = {
    "canonicals": (
        "CANONICALS.md",
        "terminology.md",
        "trust-model.md",
        "docs/operations/*.md",
        "docs/research/*.md",
        "belgi/templates/PromptBundle.blocks.md",
        "belgi/templates/DocsCompiler.template.md",
        "belgi/canonicals/CANONICALS.md",
        "belgi/canonicals/terminology.md",
        "belgi/canonicals/trust-model.md",
        "belgi/canonicals/docs/operations/*.md",
        "belgi/canonicals/docs/research/*.md",
    ),
    "gate_schema": (
        "schemas/GateVerdict.schema.json",
        "schemas/LockedSpec.schema.json",
        "schemas/ToolchainSet.schema.json",
        "schemas/Tolerances.schema.json",
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "gates/failure-taxonomy.md",
        "tiers/tier-packs.md",
        "docs/operations/cli.md",
        "docs/operations/running-belgi.md",
        "chain/compiler_c1_intent.py",
        "chain/logic/locked_object_schema.py",
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
        "chain/logic/q_checks/q4_constraints_present.py",
        "chain/logic/q_checks/q5_environment_envelope.py",
        "chain/logic/r_checks/r2_scope_budgets.py",
    ),
    "intentspec": (
        "belgi/templates/IntentSpec.core.template.md",
        "schemas/IntentSpec.schema.json",
        "schemas/LockedSpec.schema.json",
        "schemas/README.md",
        "gates/GATE_Q.md",
        "docs/operations/running-belgi.md",
        "docs/operations/cli.md",
        "chain/compiler_c1_intent.py",
        "chain/logic/q_checks/q_intent_003.py",
    ),
    "run_contract": (
        "docs/operations/cli.md",
        "docs/operations/evidence-bundles.md",
        "docs/operations/operator-anchors.md",
        "docs/operations/running-belgi.md",
        "belgi/cli_app/parser/run.py",
        "belgi/cli_app/commands/run.py",
    ),
    "schema_catalog": (
        "schemas/README.md",
        "belgi/_protocol_packs/v1/schemas/README.md",
        "chain/logic/locked_object_schema.py",
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
    ),
    "evidence": (
        "CANONICALS.md",
        "schemas/EvidenceManifest.schema.json",
        "schemas/SealManifest.schema.json",
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "tiers/tier-packs.md",
        "docs/operations/cli.md",
        "docs/operations/evidence-bundles.md",
        "docs/operations/running-belgi.md",
        "belgi/templates/DocsCompiler.template.md",
    ),
    "tiers": (
        "schemas/EvidenceManifest.schema.json",
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "tiers/tier-packs.md",
        "docs/operations/evidence-bundles.md",
        "docs/operations/running-belgi.md",
        "belgi/templates/PromptBundle.blocks.md",
    ),
    "waivers": (
        "CANONICALS.md",
        "schemas/Waiver.schema.json",
        "schemas/SealManifest.schema.json",
        "schemas/README.md",
        "tiers/tier-packs.json",
        "tiers/tier-packs.md",
        "gates/GATE_Q.md",
        "gates/GATE_R.md",
        "docs/operations/evidence-bundles.md",
        "docs/operations/waivers.md",
        "belgi/canonicals/docs/operations/waivers.md",
    ),
    "templates": (
        "CANONICALS.md",
        "schemas/EvidenceManifest.schema.json",
        "schemas/LockedSpec.schema.json",
        "gates/GATE_R.md",
        "tiers/tier-packs.md",
        "belgi/templates/PromptBundle.blocks.md",
        "belgi/templates/DocsCompiler.template.md",
    ),
    "verification_spine": (
        "schemas/LockedSpec.schema.json",
        "schemas/EvidenceManifest.schema.json",
        "schemas/GateVerdict.schema.json",
        "schemas/SealManifest.schema.json",
        "schemas/Waiver.schema.json",
        "gates/GATE_R.md",
        "chain/gate_r_verify.py",
    ),
    "orchestration": (
        "README.md",
        "CANONICALS.md",
        "schemas/*.schema.json",
        "schemas/README.md",
        "gates/*.md",
        "docs/operations/consistency-sweep.md",
        "docs/operations/workflows.md",
        "belgi/canonicals/CANONICALS.md",
        "belgi/_protocol_packs/v1/gates/*.md",
        "belgi/_protocol_packs/v1/schemas/**/*",
        "chain/logic/r_checks/*.py",
        ".github/workflows/*.yml",
        ".github/scripts/*.py",
        "scripts/belgi_*.ps1",
        "scripts/belgi_*.py",
        "scripts/belgi_*.sh",
        "templates/ci/github/*.yml",
        "tools/README.md",
        "tools/canonicals_report.py",
        "tools/normalize.py",
        "tools/rehash.py",
        "tools/sweep.py",
        "tools/consistency/common.py",
        "tools/consistency/inputs.py",
        "tools/consistency/model.py",
        "tools/consistency/registry.py",
        "tools/consistency/report_writer.py",
        "tools/consistency/runner.py",
        "tools/consistency/invariants/*.py",
    ),
    "render_views": (
        "tiers/tier-packs.json",
        "tiers/tier-packs.md",
        "tiers/tier-packs.template.md",
        "tools/render.py",
    ),
}


def _expand_pattern(pattern: str) -> list[str]:
    if any(ch in pattern for ch in "*?[]"):
        return sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in REPO_ROOT.glob(pattern)
            if path.is_file()
        )

    path = REPO_ROOT / pattern
    if path.is_dir():
        return sorted(
            child.relative_to(REPO_ROOT).as_posix()
            for child in path.rglob("*")
            if child.is_file()
        )

    if not path.is_file():
        raise FileNotFoundError(pattern)
    return [pattern]


def family_relpaths(family: str, *, extra_patterns: tuple[str, ...] = ()) -> list[str]:
    patterns = FAMILY_PATH_PATTERNS[family] + tuple(extra_patterns)
    relpaths: set[str] = set()
    for pattern in patterns:
        relpaths.update(_expand_pattern(pattern))
    return sorted(relpaths)


def copy_repo_relpaths(root: Path, relpaths: list[str]) -> None:
    for rel in relpaths:
        src = REPO_ROOT / rel
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def build_owner_family_repo(
    tmp_path: Path,
    family: str,
    *,
    extra_patterns: tuple[str, ...] = (),
    init_git: bool = True,
) -> Path:
    root = tmp_path / family
    root.mkdir(parents=True, exist_ok=True)
    copy_repo_relpaths(root, family_relpaths(family, extra_patterns=extra_patterns))
    if init_git:
        builders.init_git_repo(root)
    return root


def replace_text(root: Path, rel: str, old: str, new: str) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8", errors="strict")
    assert old in text, f"expected to find {old!r} in {rel}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8", errors="strict", newline="\n")


def replace_regex(root: Path, rel: str, pattern: str, repl: str, *, count: int = 1) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8", errors="strict")
    new_text, replaced = re.subn(pattern, repl, text, count=count, flags=re.MULTILINE)
    assert replaced == count, f"expected {count} regex replacement(s) in {rel}: {pattern!r}"
    path.write_text(new_text, encoding="utf-8", errors="strict", newline="\n")


def append_text(root: Path, rel: str, text: str) -> None:
    path = root / rel
    current = path.read_text(encoding="utf-8", errors="strict")
    path.write_text(current + text, encoding="utf-8", errors="strict", newline="\n")


def mutate_json(root: Path, rel: str, mutator: Callable[[dict[str, Any]], None]) -> None:
    path = root / rel
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(payload, dict), f"expected JSON object in {rel}"
    mutator(payload)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def remove_file(root: Path, rel: str) -> None:
    path = root / rel
    assert path.exists(), f"expected file to remove: {rel}"
    path.unlink()


def assert_invariants_pass(
    root: Path,
    cases: list[tuple[str, Callable[[Path], object]]],
) -> None:
    for invariant_id, check in cases:
        result = check(root)
        assert result.invariant_id == invariant_id
        assert result.status == "PASS", f"{invariant_id}: {result.remediation}"


def assert_invariant_fails(
    root: Path,
    invariant_id: str,
    check: Callable[[Path], object],
    expected_fragment: str,
) -> None:
    result = check(root)
    assert result.invariant_id == invariant_id
    assert result.status == "FAIL"
    evidence = "\n".join(result.evidence)
    remediation = result.remediation
    combined = f"{evidence}\n{remediation}"
    assert expected_fragment in combined, combined
