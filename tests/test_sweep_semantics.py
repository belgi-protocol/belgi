"""Regression tests for sweep helper semantics.

Goal: prevent list-returning helpers from being misread as booleans.

This specifically guards against the historic inversion bug where a check
used `if not <missing_list>:` and accidentally failed/passed the wrong way.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def test_helper_contract() -> None:
    from tools import sweep as sweep_mod

    result = sweep_mod._missing_needles("abc", ["a", "b", "c"])
    assert isinstance(result, list)
    assert result == []

    result2 = sweep_mod._missing_needles("abc", ["a", "z"])
    assert isinstance(result2, list)
    assert result2 == ["z"]


def test_known_good_must_pass(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    (tmp_path / "gates").mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates" / "GATE_Q.md").write_text(
        "\n".join(
            [
                "# Gate Q",
                "Q-INTENT-001",
                "Q-INTENT-002",
                "Q-INTENT-003",
                "IntentSpec.core.md",
                "belgi/templates/IntentSpec.core.template.md",
                "schemas/IntentSpec.schema.json",
                "schemas/LockedSpec.schema.json",
            ]
        ),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res = sweep_mod.check_cs_is_003(tmp_path)
    assert res.invariant_id == "CS-IS-003"
    assert res.status == "PASS"


def test_known_bad_must_fail(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    # Minimal synthetic repo root sufficient for CS-IS-003 (it only reads gates/GATE_Q.md).
    (tmp_path / "gates").mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates" / "GATE_Q.md").write_text(
        "\n".join(
            [
                "# Gate Q",
                "Q-INTENT-001",
                "Q-INTENT-002",
                # Intentionally omit Q-INTENT-003 and other required strings.
                "IntentSpec.core.md",
            ]
        ),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res = sweep_mod.check_cs_is_003(tmp_path)
    assert res.invariant_id == "CS-IS-003"
    assert res.status == "FAIL"


def test_abuse_no_boolean_negation_of_missing_needles() -> None:
    txt = (REPO_ROOT / "tools" / "sweep.py").read_text(encoding="utf-8", errors="strict")

    # Guardrail: reintroducing the old inverted pattern should immediately trip CI.
    assert "if not _missing_needles(" not in txt

    # Also block the positive truthiness form; callers must name the variable explicitly.
    assert re.search(r"\bif\s+_missing_needles\(", txt) is None


def test_abuse_no_boolean_truthiness_of_seal_payload_list_helpers() -> None:
    txt = (REPO_ROOT / "tools" / "sweep.py").read_text(encoding="utf-8", errors="strict")

    helpers = [
        "_seal_payload_paths_in_fixture_dir",
    ]

    for name in helpers:
        assert f"if not {name}(" not in txt
        assert re.search(rf"\bif\s+{re.escape(name)}\(", txt) is None


def _init_tracked_temp_repo(root: Path, files: dict[str, str]) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "sweep-tests@local"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Sweep Tests"], cwd=root, check=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", errors="strict", newline="\n")
    subprocess.run(["git", "add", "--all"], cwd=root, check=True)


def test_cs_term_001_fails_on_validation_posture_phrase(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "README.md": "Two-phase validation posture\n",
            "CANONICALS.md": "Deterministic verification of probabilistic proposals.\n",
        },
    )

    res = sweep_mod.check_cs_term_001(tmp_path)
    assert res.invariant_id == "CS-TERM-001"
    assert res.status == "FAIL"
    assert "README.md:1" in res.remediation
    assert "validation posture" in res.remediation


def test_cs_term_001_allows_schema_validation_context(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "README.md": "schema validation for EvidenceManifest.schema.json\n",
            "CANONICALS.md": "Deterministic verification of probabilistic proposals.\n",
        },
    )

    res = sweep_mod.check_cs_term_001(tmp_path)
    assert res.invariant_id == "CS-TERM-001"
    assert res.status == "PASS"


def test_cs_protocol_identity_001_allows_source_as_operational_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    rel = "gates/GATE_S.md"
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "note: LockedSpec.protocol_pack.source is metadata and MUST NOT be used as an identity check.\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    monkeypatch.setattr(sweep_mod, "_PROTOCOL_IDENTITY_SOURCE_GUARD_FILES", (rel,))

    res = sweep_mod.check_cs_protocol_identity_001(tmp_path)
    assert res.invariant_id == "CS-PROTOCOL-IDENTITY-001"
    assert res.status == "PASS"


def test_cs_protocol_identity_001_fails_when_source_is_in_identity_tuple(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    rel = "gates/GATE_Q.md"
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "Active protocol context identity: pack_id, manifest_sha256, pack_name, source\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    monkeypatch.setattr(sweep_mod, "_PROTOCOL_IDENTITY_SOURCE_GUARD_FILES", (rel,))

    res = sweep_mod.check_cs_protocol_identity_001(tmp_path)
    assert res.invariant_id == "CS-PROTOCOL-IDENTITY-001"
    assert res.status == "FAIL"
    assert "gates/GATE_Q.md:1" in res.remediation


def test_waiver_scope_semantics_docs_guard_prefix_not_substring() -> None:
    gate_r_text = (REPO_ROOT / "gates" / "GATE_R.md").read_text(encoding="utf-8", errors="strict")
    waivers_text = (REPO_ROOT / "docs" / "operations" / "waivers.md").read_text(encoding="utf-8", errors="strict")

    assert "literal substring (v1 deterministic scope match)" not in gate_r_text
    assert "`scope` contains the offending path as a literal substring." not in waivers_text
    assert "`scope` is a normalized repo-relative prefix" in gate_r_text
    assert "`scope` is a normalized repo-relative prefix." in waivers_text


def test_cs_can_005_passes_when_package_mirror_matches_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    source_rel = "docs/operations/running-belgi.md"
    mirror_rel = "belgi/canonicals/docs/operations/running-belgi.md"
    monkeypatch.setattr(sweep_mod, "_C3_CANONICAL_MIRROR_BINDINGS", ((source_rel, mirror_rel),))

    src = tmp_path / source_rel
    dst = tmp_path / mirror_rel
    src.parent.mkdir(parents=True, exist_ok=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("stable sha40 guidance\n", encoding="utf-8", errors="strict", newline="\n")
    dst.write_text("stable sha40 guidance\n", encoding="utf-8", errors="strict", newline="\n")

    res = sweep_mod.check_cs_can_005(tmp_path)
    assert res.invariant_id == "CS-CAN-005"
    assert res.status == "PASS"


def test_cs_can_005_fails_when_package_mirror_drifts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    source_rel = "docs/operations/running-belgi.md"
    mirror_rel = "belgi/canonicals/docs/operations/running-belgi.md"
    monkeypatch.setattr(sweep_mod, "_C3_CANONICAL_MIRROR_BINDINGS", ((source_rel, mirror_rel),))

    src = tmp_path / source_rel
    dst = tmp_path / mirror_rel
    src.parent.mkdir(parents=True, exist_ok=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("stable sha40 guidance\n", encoding="utf-8", errors="strict", newline="\n")
    dst.write_text("moving ref guidance\n", encoding="utf-8", errors="strict", newline="\n")

    res = sweep_mod.check_cs_can_005(tmp_path)
    assert res.invariant_id == "CS-CAN-005"
    assert res.status == "FAIL"
    assert mirror_rel in res.remediation
    assert source_rel in res.remediation


def test_managed_sweep_surfaces_include_package_canonicals(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "belgi/canonicals/docs/operations/running-belgi.md": "# mirror\n",
        },
    )
    managed = sweep_mod._sweep_managed_surface_files(tmp_path)
    assert "belgi/canonicals/docs/operations/running-belgi.md" in managed


def test_cs_sweep_002_fails_when_managed_surface_is_unlisted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "docs/operations/workflows.md": "# workflows\n",
            ".github/workflows/proof-tier1.yml": "name: proof\n",
            ".github/scripts/validate_belgi_ref_pin.py": "print('ok')\n",
            "scripts/belgi_latest_run.sh": "#!/usr/bin/env bash\n",
            "templates/ci/github/belgi-tier1.yml": "name: template\n",
            "tools/README.md": "# tools\n",
        },
    )

    monkeypatch.setattr(
        sweep_mod,
        "_canonical_inputs",
        lambda _root: ["tools/normalize.py", "tools/rehash.py", "tools/sweep.py"],
    )

    res = sweep_mod.check_cs_sweep_002(tmp_path)
    assert res.invariant_id == "CS-SWEEP-002"
    assert res.status == "FAIL"
    assert "docs/operations/workflows.md" in res.remediation


def test_cs_sweep_002_passes_when_managed_surface_is_listed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "docs/operations/workflows.md": "# workflows\n",
            ".github/workflows/proof-tier1.yml": "name: proof\n",
            ".github/scripts/validate_belgi_ref_pin.py": "print('ok')\n",
            "scripts/belgi_latest_run.sh": "#!/usr/bin/env bash\n",
            "templates/ci/github/belgi-tier1.yml": "name: template\n",
            "tools/README.md": "# tools\n",
        },
    )

    managed = sweep_mod._sweep_managed_surface_files(tmp_path)
    monkeypatch.setattr(
        sweep_mod,
        "_canonical_inputs",
        lambda _root: sorted(set(managed + ["tools/normalize.py", "tools/rehash.py", "tools/sweep.py"])),
    )

    res = sweep_mod.check_cs_sweep_002(tmp_path)
    assert res.invariant_id == "CS-SWEEP-002"
    assert res.status == "PASS"


def test_cs_sweep_002_fails_when_repo_root_markdown_is_unlisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "CANONICALS.md": "# canon\n",
            "README.md": "# readme\n",
            "NEW_CANONICAL.md": "# new\n",
        },
    )

    monkeypatch.setattr(
        sweep_mod,
        "_canonical_inputs",
        lambda _root: [
            "CANONICALS.md",
            "README.md",
            "tools/normalize.py",
            "tools/rehash.py",
            "tools/sweep.py",
        ],
    )

    res = sweep_mod.check_cs_sweep_002(tmp_path)
    assert res.invariant_id == "CS-SWEEP-002"
    assert res.status == "FAIL"
    assert "NEW_CANONICAL.md" in res.remediation


def test_managed_sweep_surfaces_are_covered_in_repo() -> None:
    from tools import sweep as sweep_mod

    managed = sweep_mod._sweep_managed_surface_files(REPO_ROOT)
    canon = set(sweep_mod._canonical_inputs(REPO_ROOT))
    missing = sorted(set(managed) - canon)
    assert missing == []


def _write_cs_wvr_003_fixture(
    root: Path,
    *,
    tier0_max: int,
    tier1_max: int,
    tier2_max: int,
) -> None:
    _init_tracked_temp_repo(
        root,
        {
            "tiers/tier-packs.json": (
                "{\n"
                "  \"tiers\": {\n"
                "    \"tier-0\": {\"waiver_policy\": {\"allowed\": true, \"max_active_waivers\": 20}},\n"
                "    \"tier-1\": {\"waiver_policy\": {\"allowed\": true, \"max_active_waivers\": 10}},\n"
                "    \"tier-2\": {\"waiver_policy\": {\"allowed\": true, \"max_active_waivers\": 1}},\n"
                "    \"tier-3\": {\"waiver_policy\": {\"allowed\": false, \"max_active_waivers\": 0}}\n"
                "  }\n"
                "}\n"
            ),
            "tiers/tier-packs.md": "waiver_policy\nmax_active_waivers\ntier-3\n",
            "gates/GATE_Q.md": "Q6\nVerify tier allows waivers\nmax_active_waivers\n",
            "docs/operations/waivers.md": (
                "## 5.1 Limits per tier\n"
                f"- Tier 0: waivers allowed, max {tier0_max} active\n"
                f"- Tier 1: waivers allowed, max {tier1_max} active, HOTL required (policy-level)\n"
                f"- Tier 2: waivers allowed, max {tier2_max} active, HOTL required (policy-level)\n"
                "- Tier 3: waivers not allowed\n"
            ),
        },
    )


def test_cs_wvr_003_passes_when_ops_limits_match_tiers_json(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_cs_wvr_003_fixture(tmp_path, tier0_max=20, tier1_max=10, tier2_max=1)

    res = sweep_mod.check_cs_wvr_003(tmp_path)
    assert res.invariant_id == "CS-WVR-003"
    assert res.status == "PASS"


def test_cs_wvr_003_fails_when_ops_limits_drift_from_tiers_json(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_cs_wvr_003_fixture(tmp_path, tier0_max=20, tier1_max=2, tier2_max=1)

    res = sweep_mod.check_cs_wvr_003(tmp_path)
    assert res.invariant_id == "CS-WVR-003"
    assert res.status == "FAIL"
    assert "tier-1@" in res.remediation
