from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_text(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8", errors="strict")


def test_promptbundle_template_removes_tier_pack_exact_bytes_claim() -> None:
    text = _read_text("belgi/templates/PromptBundle.blocks.md")
    text_lc = text.lower()
    assert "`../../tiers/tier-packs.json` as exact bytes at the evaluated repo revision." not in text_lc
    assert "resolved from `../../tiers/tier-packs.json`" not in text_lc

    a31_start = text_lc.index("### a3.1")
    a32_start = text_lc.index("### a3.2")
    a31 = text_lc[a31_start:a32_start]
    assert "tier policy values are selected by `lockedspec.tier.tier_id`" in a31
    assert (
        "c1 determinism must not depend on reading `tiers/tier-packs.json` from the evaluated repo revision."
        in a31
    )
    tier_lines = [ln.strip() for ln in a31.splitlines() if "tiers/tier-packs.json" in ln]
    assert tier_lines == [
        "- c1 determinism must not depend on reading `tiers/tier-packs.json` from the evaluated repo revision."
    ]


def test_docscompiler_template_routes_per_file_hashes_to_manifest() -> None:
    text_lc = _read_text("belgi/templates/DocsCompiler.template.md").lower()
    assert "for each file: normalized output hash" not in text_lc
    assert (
        "per-file normalized output hashes are published via `bundle/docs_bundle_manifest.json` (`files[]`"
        " path+sha256); they are not required as direct fields in the `docs_compilation_log` payload."
    ) in text_lc


def test_running_belgi_docs_require_canonical_out_log_path() -> None:
    text_lc = _read_text("docs/operations/running-belgi.md").lower()
    assert "`--out-log` must be exactly `docs/docs_compilation_log.json`." in text_lc
    assert "this fixed path is required for deterministic discovery and evidence indexability." in text_lc


def test_r7_public_docs_are_explicitly_bounded() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    canonicals = _read_text("CANONICALS.md")
    canonicals_mirror = _read_text("belgi/canonicals/CANONICALS.md")
    evidence_bundles = _read_text("docs/operations/evidence-bundles.md")
    evidence_bundles_mirror = _read_text("belgi/canonicals/docs/operations/evidence-bundles.md")

    required_gate_r = (
        "repo-state / change-surface signal grounded in workspace/revision state and declared evidence"
    )
    required_non_claims = (
        "does not claim SBOM generation/verification, provenance or SLSA-style builder attestation, "
        "dependency vulnerability scanning, or a full dependency/toolchain inventory beyond declared evidence surfaces"
    )
    required_canonicals = (
        "This does not claim SBOM generation/verification, provenance attestation, dependency vulnerability scanning, "
        "or a full dependency/toolchain inventory beyond declared evidence."
    )
    required_evidence_bundles = (
        "Bounded meaning: repo-state / change-surface signal only; not an SBOM, provenance-attestation, "
        "or dependency-vulnerability-scanner contract"
    )

    assert required_gate_r in gate_r
    assert required_non_claims in gate_r
    for text in (canonicals, canonicals_mirror):
        assert required_canonicals in text
    for text in (evidence_bundles, evidence_bundles_mirror):
        assert required_evidence_bundles in text


def test_r7_docs_keep_pinned_toolchain_refs_owned_by_q5() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    rendered_tiers = _read_text("tiers/tier-packs.md")
    pack_gate_r = _read_text("belgi/_protocol_packs/v1/gates/GATE_R.md")
    pack_rendered_tiers = _read_text("belgi/_protocol_packs/v1/tiers/tier-packs.md")

    owner_note = (
        "Q5 owns `envelope_policy.pinned_toolchain_refs_required`; R7 consumes declared "
        "`LockedSpec.environment_envelope.pinned_toolchain_refs` as evidence context but does not read that tier parameter."
    )
    old_gate_r_line = "- tier params used: `envelope_policy.pinned_toolchain_refs_required`, `command_log_mode`"
    new_rendered_line = "| R7 | command_log_mode |"
    old_rendered_line = "| R7 | envelope_policy.pinned_toolchain_refs_required, command_log_mode |"

    for text in (gate_r, pack_gate_r):
        assert owner_note in text
        assert old_gate_r_line not in text

    for text in (rendered_tiers, pack_rendered_tiers):
        assert "| Q5 | envelope_policy.pinned_toolchain_refs_required |" in text
        assert new_rendered_line in text
        assert old_rendered_line not in text


def test_waiver_docs_split_mechanical_and_operational_controls() -> None:
    waivers = _read_text("docs/operations/waivers.md")
    waivers_mirror = _read_text("belgi/canonicals/docs/operations/waivers.md")

    for text in (waivers, waivers_mirror):
        assert (
            "Repo-mechanical enforcement in v1 proves schema validity, active status, placeholder rejection, "
            "the human-authorship heuristic, anchored expiry replay, and tier limits."
        ) in text
        assert (
            "BELGI does not mechanically prove branch protection, restricted storage, actor/source provenance, "
            "or approval workflow provenance from in-repo artifacts alone; those remain operational controls."
        ) in text

        section = text[text.index("### 4.2 Operational controls outside repo-mechanical proof") :]
        assert "branch protection and restricted storage for waiver sources" in section
        assert "actor/source provenance for who authored or moved a waiver artifact" in section
        assert "approval workflow provenance showing how human review/approval happened" in section


def test_prompt_hash_contract_explicitly_requires_c1_rendered_bytes_hashes() -> None:
    required_a = "Each hash MUST equal `sha256(C1_rendered_block_bytes)` for the selected prompt blocks."
    required_b = "C3 recomputes expected hashes by rendering the selected prompt blocks and rejects mismatches."

    running_docs = _read_text("docs/operations/running-belgi.md")
    mirror_docs = _read_text("belgi/canonicals/docs/operations/running-belgi.md")
    c3_template = _read_text("belgi/templates/DocsCompiler.template.md")

    for text in (running_docs, mirror_docs, c3_template):
        assert required_a in text
        assert required_b in text


def test_gate_r_fail_fast_doctrine_docs_are_explicit() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    gate_r_pack = _read_text("belgi/_protocol_packs/v1/gates/GATE_R.md")
    running_docs = _read_text("docs/operations/running-belgi.md")
    running_docs_mirror = _read_text("belgi/canonicals/docs/operations/running-belgi.md")

    doctrine = "Gate R default doctrine is **fail-fast / minimal mutation**."
    executed_only = "`results[]` contains executed checks only."
    identity_stop = (
        "If `PROTOCOL-IDENTITY-001` fails, Gate R stops before mutation-producing snapshot work"
    )
    snapshot_stop = (
        "Snapshot manifest/index write failure is terminal because Gate R must not continue later evaluation without a persisted evidence anchor."
    )

    for text in (gate_r, gate_r_pack, running_docs, running_docs_mirror):
        assert doctrine in text
        assert executed_only in text
        assert snapshot_stop in text

    for text in (gate_r, gate_r_pack):
        assert "Gate R MUST stop before mutation-producing snapshot work" in text

    for text in (running_docs, running_docs_mirror):
        assert identity_stop in text
