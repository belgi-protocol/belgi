from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_text(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8", errors="strict")


def test_promptbundle_template_selects_policy_blocks_from_owner_values() -> None:
    text = _read_text("belgi/templates/PromptBundle.blocks.md")

    assert (
        '| PB-009 | Command Log Mode Reminder | constraints | Tier defaults: '
        '`../../tiers/tier-packs.json` (`command_log_mode`) | `command_log_mode == "structured"` | public |'
    ) in text
    assert (
        '| PB-010 | Tests Policy Reminder | constraints | Tier defaults: '
        '`../../tiers/tier-packs.json` (`test_policy`); Gate R ref: '
        '`../../gates/GATE_R.md#r5--tests-policy-satisfied` | `test_policy.required == true` | public |'
    ) in text
    assert (
        '| PB-011 | Envelope Attestation Reminder | constraints | Tier defaults: '
        '`../../tiers/tier-packs.json` (`envelope_policy`); Gate R ref: '
        '`../../gates/GATE_R.md#r6--envelope-attestation-satisfied` | '
        '`envelope_policy.requires_attestation == true` | public |'
    ) in text

    a32_start = text.index("### A3.2")
    a33_start = text.index("### A3.3")
    a32 = text[a32_start:a33_start]
    assert "Selection function `selected_blocks(tier_policy)`:" in a32
    assert '- If `tier_policy.command_log_mode == "structured"`, additionally include: PB-009.' in a32
    assert '- If `tier_policy.test_policy.required == true`, additionally include: PB-010.' in a32
    assert (
        '- If `tier_policy.envelope_policy.requires_attestation == true`, additionally include: PB-011.'
        in a32
    )
    assert "If `tier_id` is one of `tier-1`, `tier-2`, `tier-3`, additionally include: PB-009, PB-010, PB-011." not in a32


def test_r7_owner_docs_are_explicitly_bounded() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    canonicals = _read_text("CANONICALS.md")
    evidence_bundles = _read_text("docs/operations/evidence-bundles.md")

    required_gate_r = "deterministic declared change-accounting over the actual locked-base -> evaluated diff"
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
    assert required_canonicals in canonicals
    assert required_evidence_bundles in evidence_bundles


def test_waiver_docs_split_mechanical_and_operational_controls() -> None:
    waivers = _read_text("docs/operations/waivers.md")

    assert (
        "Repo-mechanical enforcement in v1 proves schema validity, active status, placeholder rejection, "
        "the human-authorship heuristic, anchored expiry replay, and tier limits."
    ) in waivers
    assert (
        "BELGI does not mechanically prove branch protection, restricted storage, actor/source provenance, "
        "or approval workflow provenance from in-repo artifacts alone; those remain operational controls."
    ) in waivers

    section = waivers[waivers.index("### 4.2 Operational controls outside repo-mechanical proof") :]
    assert "branch protection and restricted storage for waiver sources" in section
    assert "actor/source provenance for who authored or moved a waiver artifact" in section
    assert "approval workflow provenance showing how human review/approval happened" in section


def test_gate_r_fail_fast_doctrine_docs_are_explicit() -> None:
    gate_r = _read_text("gates/GATE_R.md")

    doctrine = "Gate R default doctrine is **fail-fast / minimal mutation**."
    executed_only = "`results[]` contains executed checks only."
    snapshot_stop = (
        "Snapshot manifest/index write failure is terminal because Gate R must not continue later evaluation without a persisted evidence anchor."
    )

    assert doctrine in gate_r
    assert executed_only in gate_r
    assert snapshot_stop in gate_r
    assert "Gate R MUST stop before mutation-producing snapshot work" in gate_r

def test_required_report_payloads_are_explicitly_bound_to_current_run() -> None:
    gate_r = _read_text("gates/GATE_R.md")

    required_policy = "Required `policy_report` payloads MUST have `payload.run_id == LockedSpec.run_id`."
    required_test = "Required `test_report` payloads MUST have `payload.run_id == LockedSpec.run_id`."

    assert required_policy in gate_r
    assert required_test in gate_r


def test_required_report_current_run_binding_is_owned_by_r4_only() -> None:
    gate_r = _read_text("gates/GATE_R.md")

    required_owner = (
        "Gate R applies this required-report current-run binding structurally under `R4` before semantic checks "
        "(`R1`, `R5`, `R7`, `R8`) rely on those required report payloads."
    )

    assert required_owner in gate_r


def test_r8_public_docs_match_runtime_contract() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    failure_taxonomy = _read_text("gates/failure-taxonomy.md")

    command_rule = "successful execution means `exit_code == 0` only"
    findings_mode_line = "semantic verdicting is driven by `adversarial_policy.findings_mode`"
    diff_subject_line = "changed Python lines on the actual locked-base -> evaluated diff as the primary scan subject"
    diff_guard_line = "Findings outside the actual diff MUST NOT by themselves drive `summary.failed != 0`"
    warn_line = (
        '`findings_mode == "warn"`: findings do not themselves cause `R8` to fail if command/report/waiver '
        "structure is otherwise valid."
    )
    fail_line = (
        '`findings_mode == "fail"`: if the accepted report indicates failures (`summary.failed != 0`) and one or '
        "more findings remain unwaived, fail `FR-ADVERSARIAL-DIFF-SUSPECT`."
    )
    waiver_pass_line = (
        "If findings are present but all findings are covered by applicable active waivers allowed by the selected "
        "tier, `R8` PASSes."
    )
    running_docs_command = (
        "R8 command success is satisfied only by a `belgi adversarial-scan` command record with `exit_code == 0`."
    )
    running_docs_diff_subject = (
        "Current shipped R8 producer uses changed Python lines from the actual `base_revision -> evaluated_revision` "
        "diff as the primary scan subject."
    )
    running_docs_diff_guard = (
        "Findings outside the actual diff do not by themselves produce `FR-ADVERSARIAL-DIFF-SUSPECT`."
    )
    running_docs_warn = (
        'When `adversarial_policy.findings_mode == "warn"`, findings do not themselves cause `R8` to fail if '
        "command/report/waiver structure is otherwise valid."
    )
    running_docs_fail = (
        'When `adversarial_policy.findings_mode == "fail"`, unwaived findings can produce '
        "`FR-ADVERSARIAL-DIFF-SUSPECT`."
    )
    running_docs_waiver = (
        "If findings are present but all findings are covered by applicable active waivers allowed by the selected "
        "tier, `R8` can PASS."
    )
    stale_rc2 = "rc=2"
    stale_flat_fail = "if the accepted report indicates failures (`summary.failed != 0`) => fail `FR-ADVERSARIAL-DIFF-SUSPECT`."

    assert command_rule in gate_r
    assert findings_mode_line in gate_r
    assert diff_subject_line in gate_r
    assert diff_guard_line in gate_r
    assert warn_line in gate_r
    assert fail_line in gate_r
    assert waiver_pass_line in gate_r
    assert stale_rc2 not in gate_r.lower()
    assert stale_flat_fail not in gate_r.lower()

    assert '`adversarial_policy.findings_mode == "fail"`' in failure_taxonomy
    assert "one or more unwaived findings (`summary.failed != 0`)" in failure_taxonomy
    assert "is not emitted in `warn` mode" in failure_taxonomy
    assert "is not emitted when all findings are covered by applicable active waivers" in failure_taxonomy


def test_r2_public_docs_match_locked_tolerances_contract() -> None:
    gate_q = _read_text("gates/GATE_Q.md")
    gate_r = _read_text("gates/GATE_R.md")
    failure_taxonomy = _read_text("gates/failure-taxonomy.md")

    gate_r_locked_object = "Resolve `LockedSpec.tier.tolerances_ref` and read the locked ceiling values:"
    gate_r_no_tier_defaults = "`max_touched_files` = `LockedSpec.constraints.max_touched_files` if present else tier default."
    gate_r_no_hotl = "adjust tier/constraints with HOTL"
    cli_tolerances_flag = "`--tolerances-ref <object_id>=<repo-relative-path>` (singular)"
    cli_tolerances_binding = "binds a real locked tolerances object into `LockedSpec.tier.tolerances_ref`"
    cli_tolerances_pre_lock = "the referenced Tolerances file is a pre-lock operator input"
    cli_tolerances_tier_match = "`Tolerances.tier_id` must match the selected tier"
    cli_tolerances_tighten = (
        "may equal or tighten the selected tier ceilings, but BELGI rejects wider values"
    )
    running_default = (
        "if shipped `belgi run` omits Tolerances, orchestration generates the canonical tolerances object "
        "from the selected tier pack before lock"
    )
    running_boundary = (
        "on the shipped `belgi run` spine, current-run ToolchainSet/Tolerances inputs are staged into "
        "locked/store authority before C1"
    )
    running_manual_boundary = (
        "manual C1 uses repo-relative `--toolchain-set` / `--tolerances` inputs instead of shipped `belgi run` refs"
    )
    gate_q_tighten = "to be equal to or stricter than the selected tier ceilings; reject any wider value"
    gate_q_remediation = (
        "Do lock a valid tier.tolerances_ref object for the selected tier that stays within the selected tier ceilings, then re-run Q."
    )
    running_numeric_retired = (
        "Numeric scope budgets no longer live in `IntentSpec`; schema and runtime both reject legacy "
        "`IntentSpec.scope.max_*` fields with migration guidance."
    )
    failure_taxonomy_line = (
        "`Do reduce scope to within the locked tolerances ceilings or change the locked Tolerances object / "
        "selected tier and re-run Q, then re-run R.`"
    )

    assert "Resolve `LockedSpec.tier.tolerances_ref`" in gate_q
    assert gate_q_tighten in gate_q
    assert gate_q_remediation in gate_q

    assert gate_r_locked_object in gate_r
    assert gate_r_no_tier_defaults not in gate_r
    assert gate_r_no_hotl not in gate_r
    assert "scope_budgets.max_touched_files" in gate_r
    assert "scope_budgets.max_loc_delta" in gate_r

    assert failure_taxonomy_line in failure_taxonomy


def test_r7_public_docs_match_runtime_contract() -> None:
    gate_r = _read_text("gates/GATE_R.md")

    bounded_meaning = "deterministic declared change-accounting over the actual locked-base -> evaluated diff"
    declaration_surface_line = "changed paths whose basename matches `requirements*.txt` or `constraints*.txt`"
    accounting_context_line = (
        "using `LockedSpec.environment_envelope.pinned_toolchain_refs[].storage_ref` as the accounting context "
        "derived from the locked ToolchainSet plus built-in `toolchain.main`."
    )
    running_docs_meaning = (
        "Current shipped R7 producer uses the actual `base_revision -> evaluated_revision` diff and limits "
        "`FR-SUPPLYCHAIN-CHANGE-UNACCOUNTED` to bounded dependency/toolchain declaration paths plus declared "
        "ToolchainSet paths."
    )
    running_docs_accounting = (
        "The current R7 accounting context is the declared "
        "`LockedSpec.environment_envelope.pinned_toolchain_refs[].storage_ref` set derived from the locked ToolchainSet "
        "plus built-in `toolchain.main`."
    )
    cli_binding = (
        "binds an authoritative ToolchainSet object into `LockedSpec.environment_envelope.toolchain_set_ref`"
    )
    cli_pre_lock = "the referenced ToolchainSet file is a pre-lock operator input"
    cli_member_guard = (
        "ToolchainSet member declaration paths must still point at actual repo-relative dependency/toolchain "
        "declaration surfaces in the evaluated revision truth envelope"
    )
    running_ingress = (
        "For the shared environment objects on the shipped spine, keep only this execution boundary in mind: "
        "current-run ToolchainSet/Tolerances inputs are staged into locked/store authority before C1, while "
        "manual C1 still uses repo-relative `--toolchain-set` / `--tolerances` inputs."
    )
    running_member_guard = (
        "Shorthand `--toolchain-ref` declaration paths, and ToolchainSet member declaration paths inside "
        "the locked object, must still exist in the evaluated revision truth envelope."
    )
    gate_r_shipped_ingress = (
        "explicit ToolchainSet refs are pre-lock operator inputs accepted only at "
        "`.belgi/runs/<run_id>/inputs/environment/toolchain-set.json` for the current run"
    )
    reserved_main = "`toolchain.main` is reserved for the built-in generated run toolchain input"

    assert bounded_meaning in gate_r
    assert declaration_surface_line in gate_r
    assert accounting_context_line in gate_r
    assert gate_r_shipped_ingress in gate_r
    assert "ToolchainSet" in gate_r


def test_tier3_owner_docs_are_explicit() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    evidence = _read_text("docs/operations/evidence-bundles.md")
    trust_model = _read_text("trust-model.md")
    genesis_readme = _read_text("belgi/genesis/README.md")

    canonical_root = "Tier-3 canonical authority is rooted in `belgi/anchor/v1/TrustAnchor.json`."
    canonical_root_gate_r = "Tier-3 canonical authority is rooted in [../belgi/anchor/v1/TrustAnchor.json]"
    evidence_boundary = (
        "`genesis_seal` is the Tier-3 evidence kind; `TrustAnchor.json` is the canonical authority object used to verify that evidence."
    )
    repo_primary = "Internet publication of the trust anchor is secondary only; the repo artifact is the primary Tier-3 authority surface."
    history_boundary = (
        "`belgi/genesis/GenesisSealPayload.json` remains a historical repo-local genesis reference payload"
    )

    assert canonical_root in evidence
    assert canonical_root in trust_model
    assert canonical_root_gate_r in gate_r
    assert evidence_boundary in evidence
    assert repo_primary in evidence
    assert "the repo artifact is the primary authority surface." in trust_model
    assert history_boundary in trust_model
    assert "historical repo-local genesis reference payload" in genesis_readme
    assert "it is not authoritative for canonical Tier-3 trust-anchor verification" in genesis_readme
    assert "Canonical Tier-3 authority begins with" in genesis_readme


def test_genesis_seal_schema_description_keeps_trust_anchor_boundary() -> None:
    schema_text = _read_text("schemas/GenesisSealPayload.schema.json")
    assert "root-of-trust payload" not in schema_text
    assert "validated under the canonical TrustAnchor authority artifact" in schema_text
    assert "not itself the Tier-3 authority object" in schema_text
