from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_C3_CANONICAL_DOC_MIRRORS: tuple[tuple[str, str], ...] = (
    ("CANONICALS.md", "belgi/canonicals/CANONICALS.md"),
    ("terminology.md", "belgi/canonicals/terminology.md"),
    ("trust-model.md", "belgi/canonicals/trust-model.md"),
    ("docs/operations/consistency-sweep.md", "belgi/canonicals/docs/operations/consistency-sweep.md"),
    ("docs/operations/cli.md", "belgi/canonicals/docs/operations/cli.md"),
    ("docs/operations/evidence-bundles.md", "belgi/canonicals/docs/operations/evidence-bundles.md"),
    ("docs/operations/evidence-ownership.md", "belgi/canonicals/docs/operations/evidence-ownership.md"),
    ("docs/operations/operator-anchors.md", "belgi/canonicals/docs/operations/operator-anchors.md"),
    ("docs/operations/running-belgi.md", "belgi/canonicals/docs/operations/running-belgi.md"),
    ("docs/operations/security.md", "belgi/canonicals/docs/operations/security.md"),
    ("docs/operations/waivers.md", "belgi/canonicals/docs/operations/waivers.md"),
    ("docs/research/README.md", "belgi/canonicals/docs/research/README.md"),
    ("docs/research/experiment-design.md", "belgi/canonicals/docs/research/experiment-design.md"),
    ("docs/research/metrics.md", "belgi/canonicals/docs/research/metrics.md"),
)

_PROTOCOL_PACK_TEXT_MIRRORS: tuple[tuple[str, str], ...] = (
    ("schemas/README.md", "belgi/_protocol_packs/v1/schemas/README.md"),
    ("gates/GATE_Q.md", "belgi/_protocol_packs/v1/gates/GATE_Q.md"),
    ("gates/GATE_R.md", "belgi/_protocol_packs/v1/gates/GATE_R.md"),
    ("gates/failure-taxonomy.md", "belgi/_protocol_packs/v1/gates/failure-taxonomy.md"),
    ("tiers/tier-packs.md", "belgi/_protocol_packs/v1/tiers/tier-packs.md"),
    (
        "schemas/GenesisSealPayload.schema.json",
        "belgi/_protocol_packs/v1/schemas/GenesisSealPayload.schema.json",
    ),
)


def _read_text(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8", errors="strict")


def _read_bytes(relpath: str) -> bytes:
    return (REPO_ROOT / relpath).read_bytes()


def test_c3_canonical_doc_mirrors_are_byte_identical() -> None:
    for src_rel, dst_rel in _C3_CANONICAL_DOC_MIRRORS:
        assert _read_bytes(src_rel) == _read_bytes(dst_rel)


def test_protocol_pack_text_mirrors_are_byte_identical() -> None:
    for src_rel, dst_rel in _PROTOCOL_PACK_TEXT_MIRRORS:
        assert _read_bytes(src_rel) == _read_bytes(dst_rel)


def test_promptbundle_template_removes_tier_pack_exact_bytes_claim() -> None:
    text = _read_text("belgi/templates/PromptBundle.blocks.md")
    text_lc = text.lower()
    assert "`../../tiers/tier-packs.json` as exact bytes at the evaluated repo revision." not in text_lc
    assert "resolved from `../../tiers/tier-packs.json`" not in text_lc
    assert (
        "| PB-006 | Tolerances: Scope Budgets Object | constraints | LockedSpec field: "
        "`tier.tolerances_ref` | always | internal | Provides the locked Tolerances object "
        "reference that governs scope-budget ceilings. |"
    ) in text

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


def test_running_belgi_manual_c1_example_matches_current_object_contract() -> None:
    running_docs = _read_text("docs/operations/running-belgi.md")

    assert "--toolchain-set env.toolchains=bundle/environment/toolchain-set.json" in running_docs
    assert "--toolchain-ref toolchain.main=bundle/environment/toolchain.json" in running_docs
    assert "--tolerances tier.tolerances=bundle/environment/tolerances.json" in running_docs
    assert "--toolchain-ref tc-001=bundle/toolchains/toolchain-001.json" not in running_docs
    assert "--tolerances tol-001=bundle/tolerances/tol-001.json" not in running_docs
    assert "do not pass them as extra shorthand `--toolchain-ref` values" in running_docs
    assert "The explicit CLI flags remain repo-relative and do not require a hardcoded workspace location." not in running_docs


def test_schema_readmes_claim_published_schema_backed_locked_objects() -> None:
    schema_readme = _read_text("schemas/README.md")
    required_line = (
        "Gate Q / Gate R locked-object loaders validate ToolchainSet and Tolerances "
        "against these published schemas after ObjectRef hash binding."
    )

    assert required_line in schema_readme
    assert "schema and runtime both reject legacy `IntentSpec.scope.max_*` fields" in schema_readme


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


def test_r7_docs_keep_pinned_toolchain_refs_owned_by_q5() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    rendered_tiers = _read_text("tiers/tier-packs.md")

    owner_note = (
        "Q5 owns `envelope_policy.pinned_toolchain_refs_required`; R7 consumes the normalized "
        "`LockedSpec.environment_envelope.pinned_toolchain_refs` evidence context derived from `toolchain_set_ref` "
        "but does not read that tier parameter."
    )
    old_gate_r_line = "- tier params used: `envelope_policy.pinned_toolchain_refs_required`, `command_log_mode`"
    new_rendered_line = "| R7 | command_log_mode |"
    old_rendered_line = "| R7 | envelope_policy.pinned_toolchain_refs_required, command_log_mode |"

    assert owner_note in gate_r
    assert old_gate_r_line not in gate_r
    assert "| Q5 | envelope_policy.pinned_toolchain_refs_required |" in rendered_tiers
    assert new_rendered_line in rendered_tiers
    assert old_rendered_line not in rendered_tiers


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


def test_operator_anchor_owner_docs_keep_boundary_and_term_claims() -> None:
    canonicals = _read_text("CANONICALS.md")
    terminology = _read_text("terminology.md")
    cli_docs = _read_text("docs/operations/cli.md")
    anchors_docs = _read_text("docs/operations/operator-anchors.md")

    required_definition = "Operator Anchors are operator-supplied control artifacts or refs"
    required_boundary = "`genesis_seal` remains Tier-3 evidence"
    term_pointer = "| Operator Anchors | [CANONICALS.md#operator-anchors](CANONICALS.md#operator-anchors) |"
    anchors_boundary = "Adjacent non-anchor Tier-3 evidence workspace:"

    assert required_definition in canonicals
    assert required_boundary in canonicals
    assert term_pointer in terminology

    assert "inputs/anchors/" in cli_docs
    assert "inputs/evidence/genesis_seal.json" in cli_docs
    assert "inputs/tier2/" not in cli_docs
    assert "inputs/tier3/" not in cli_docs

    assert anchors_boundary in anchors_docs
    assert ".belgi/runs/<run_id>/inputs/anchors/approvals/" in anchors_docs
    assert ".belgi/runs/<run_id>/inputs/anchors/keys/" in anchors_docs
    assert ".belgi/runs/<run_id>/inputs/anchors/signing/" in anchors_docs
    assert ".belgi/runs/<run_id>/inputs/evidence/genesis_seal.json" in anchors_docs
    assert "`genesis_seal` is not an Operator Anchor." in anchors_docs
    assert "belgi run \\" not in anchors_docs


def test_prompt_hash_contract_explicitly_requires_c1_rendered_bytes_hashes() -> None:
    required_a = "Each hash MUST equal `sha256(C1_rendered_block_bytes)` for the selected prompt blocks."
    required_b = "C3 recomputes expected hashes by rendering the selected prompt blocks and rejects mismatches."

    running_docs = _read_text("docs/operations/running-belgi.md")
    c3_template = _read_text("belgi/templates/DocsCompiler.template.md")

    assert required_a in running_docs
    assert required_b in running_docs
    assert required_a in c3_template
    assert required_b in c3_template


def test_gate_r_fail_fast_doctrine_docs_are_explicit() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    running_docs = _read_text("docs/operations/running-belgi.md")

    doctrine = "Gate R default doctrine is **fail-fast / minimal mutation**."
    executed_only = "`results[]` contains executed checks only."
    identity_stop = (
        "If `PROTOCOL-IDENTITY-001` fails, Gate R stops before mutation-producing snapshot work"
    )
    snapshot_stop = (
        "Snapshot manifest/index write failure is terminal because Gate R must not continue later evaluation without a persisted evidence anchor."
    )

    assert doctrine in gate_r
    assert executed_only in gate_r
    assert snapshot_stop in gate_r
    assert "Gate R MUST stop before mutation-producing snapshot work" in gate_r

    assert doctrine in running_docs
    assert executed_only in running_docs
    assert snapshot_stop in running_docs
    assert identity_stop in running_docs


def test_required_report_payloads_are_explicitly_bound_to_current_run() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    running_docs = _read_text("docs/operations/running-belgi.md")

    required_policy = "Required `policy_report` payloads MUST have `payload.run_id == LockedSpec.run_id`."
    required_test = "Required `test_report` payloads MUST have `payload.run_id == LockedSpec.run_id`."
    required_ops = (
        "Required `policy_report` and `test_report` payloads are not accepted on schema/hash validity alone; "
        "they must also bind to the current run via `payload.run_id == LockedSpec.run_id`."
    )

    assert required_policy in gate_r
    assert required_test in gate_r
    assert required_ops in running_docs


def test_required_report_current_run_binding_is_owned_by_r4_only() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    running_docs = _read_text("docs/operations/running-belgi.md")

    required_owner = (
        "Gate R applies this required-report current-run binding structurally under `R4` before semantic checks "
        "(`R1`, `R5`, `R7`, `R8`) rely on those required report payloads."
    )
    required_ops = (
        "Required `policy_report` and `test_report` payloads are structurally accepted under `R4` before semantic "
        "checks consume them."
    )

    assert required_owner in gate_r
    assert required_ops in running_docs


def test_r8_public_docs_match_runtime_contract() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    running_docs = _read_text("docs/operations/running-belgi.md")
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

    assert running_docs_command in running_docs
    assert "R8 semantic verdicting is driven by `adversarial_policy.findings_mode`" in running_docs
    assert running_docs_diff_subject in running_docs
    assert running_docs_diff_guard in running_docs
    assert running_docs_warn in running_docs
    assert running_docs_fail in running_docs
    assert running_docs_waiver in running_docs

    assert '`adversarial_policy.findings_mode == "fail"`' in failure_taxonomy
    assert "one or more unwaived findings (`summary.failed != 0`)" in failure_taxonomy
    assert "is not emitted in `warn` mode" in failure_taxonomy
    assert "is not emitted when all findings are covered by applicable active waivers" in failure_taxonomy


def test_r2_public_docs_match_locked_tolerances_contract() -> None:
    gate_q = _read_text("gates/GATE_Q.md")
    gate_r = _read_text("gates/GATE_R.md")
    cli_docs = _read_text("docs/operations/cli.md")
    running_docs = _read_text("docs/operations/running-belgi.md")
    rendered_tiers = _read_text("tiers/tier-packs.md")
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

    assert cli_tolerances_flag in cli_docs
    assert cli_tolerances_binding in cli_docs
    assert cli_tolerances_pre_lock in cli_docs
    assert cli_tolerances_tier_match in cli_docs
    assert cli_tolerances_tighten in cli_docs
    assert "materializes the canonical tolerances object from the selected tier pack" in cli_docs
    assert "numeric scope budgets no longer live in `IntentSpec`" in cli_docs

    assert running_default in running_docs
    assert running_boundary in running_docs
    assert running_manual_boundary in running_docs
    assert running_numeric_retired in running_docs
    assert "R2 semantic budget ceilings come from the locked `LockedSpec.tier.tolerances_ref` object" in running_docs
    assert "`--tolerances-ref <object_id>=<repo-relative-path>`" not in running_docs

    assert "| Q4 | scope_budgets.max_touched_files, scope_budgets.max_loc_delta |" in rendered_tiers
    assert "| R2 | scope_budgets.max_touched_files, scope_budgets.max_loc_delta |" not in rendered_tiers
    assert "The run-local Tolerances object locked at `LockedSpec.tier.tolerances_ref` is the runtime budget authority after lock." in rendered_tiers

    assert failure_taxonomy_line in failure_taxonomy


def test_consistency_sweep_docs_keep_shipped_and_manual_object_flags_distinct() -> None:
    sweep_docs = _read_text("docs/operations/consistency-sweep.md")

    required_running_line = (
        "non-owner operator docs MUST point exact shipped CLI syntax/examples back to `docs/operations/cli.md` "
        "instead of duplicating full flag catalogs."
    )
    required_tier3_line = (
        "non-owner Tier-3 reminders MUST point `genesis_seal` / `TrustAnchor.json` authority semantics back "
        "to `docs/operations/evidence-bundles.md` and `../../CANONICALS.md` instead of restating full authority prose."
    )
    required_anchors_line = "Confirm `docs/operations/operator-anchors.md` teaches:"
    stale_line = "run new guidance promotes authoritative environment inputs"

    assert required_running_line in sweep_docs
    assert required_tier3_line in sweep_docs
    assert required_anchors_line in sweep_docs
    assert stale_line not in sweep_docs


def test_r7_public_docs_match_runtime_contract() -> None:
    gate_r = _read_text("gates/GATE_R.md")
    cli_docs = _read_text("docs/operations/cli.md")
    running_docs = _read_text("docs/operations/running-belgi.md")

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

    assert "`--toolchain-set-ref <object_id>=<repo-relative-path>` (singular)" in cli_docs
    assert "`--toolchain-ref <object_id>=<repo-relative-path>` (repeatable)" in cli_docs
    assert cli_binding in cli_docs
    assert "normalizes these refs into authoritative ToolchainSet object authority before lock" in cli_docs
    assert cli_pre_lock in cli_docs
    assert cli_member_guard in cli_docs
    assert reserved_main in cli_docs
    assert "this is not an Operator Anchor" in cli_docs

    assert "R7 semantic verdicting is driven by the accepted `policy.supplychain` report after `R4` structural acceptance." in running_docs
    assert running_docs_meaning in running_docs
    assert running_docs_accounting in running_docs
    assert running_ingress in running_docs
    assert running_member_guard in running_docs
    assert "`--toolchain-set-ref <object_id>=<repo-relative-path>`" not in running_docs


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
