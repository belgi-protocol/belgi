from __future__ import annotations

from pathlib import Path

from tests.helpers import subprocess_cli as cli_subprocess

run_belgi = cli_subprocess.run_belgi


def test_run_new_idempotent_and_force(tmp_path: Path) -> None:
    assert run_belgi(["init", "--repo", str(tmp_path)]) == 0

    run_id = "run-demo-001"
    run_dir = tmp_path / ".belgi" / "runs" / run_id
    intent_path = run_dir / "inputs" / "intent" / "IntentSpec.core.md"
    waivers_dir = run_dir / "inputs" / "waivers"
    anchors_dir = run_dir / "inputs" / "anchors"
    approvals_dir = anchors_dir / "approvals"
    keys_dir = anchors_dir / "keys"
    signing_dir = anchors_dir / "signing"
    evidence_dir = run_dir / "inputs" / "evidence"
    runbook_template_path = run_dir / "RUN.md"
    run_key_pointer_path = run_dir / "run_key.txt"
    last_attempt_pointer_path = run_dir / "last_attempt.txt"
    open_verdict_pointer_path = run_dir / "open_verdict.txt"
    open_evidence_pointer_path = run_dir / "open_evidence.txt"
    deprecated_intent_template_path = run_dir / "IntentSpec.md"
    environment_dir = run_dir / "inputs" / "environment"
    tolerances_path = run_dir / "tolerances.json"
    toolchain_path = run_dir / "toolchain.json"

    rc1 = run_belgi(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc1 == 0
    assert intent_path.exists()
    assert waivers_dir.exists()
    assert waivers_dir.is_dir()
    assert list(waivers_dir.iterdir()) == []
    assert anchors_dir.is_dir()
    assert approvals_dir.is_dir()
    assert keys_dir.is_dir()
    assert signing_dir.is_dir()
    assert evidence_dir.is_dir()
    assert environment_dir.is_dir()
    assert not (run_dir / "inputs" / "tier2").exists()
    assert not (run_dir / "inputs" / "tier3").exists()
    assert runbook_template_path.exists()
    assert not deprecated_intent_template_path.exists()
    runbook_text = runbook_template_path.read_text(encoding="utf-8", errors="strict")
    assert "belgi waiver new --repo . --run-id" in runbook_text
    assert "belgi waiver apply --repo . --run-id" in runbook_text
    assert "belgi run --repo . --tier tier-1 --intent-spec .belgi/runs/" in runbook_text
    assert "--base-revision" in runbook_text
    assert "inputs/intent/IntentSpec.core.md" in runbook_text
    assert "inputs/waivers/waiver-001.json" in runbook_text
    assert "Operator Anchors" in runbook_text
    assert "inputs/anchors/approvals/hotl_approval.json" in runbook_text
    assert "inputs/anchors/keys/attestation_pubkey.hex" in runbook_text
    assert "inputs/anchors/signing/seal_signature.b64" in runbook_text
    assert "inputs/evidence/genesis_seal.json" in runbook_text
    assert "mkdir -p .belgi/runs/run-demo-001/inputs/environment" in runbook_text
    assert "cat > .belgi/runs/run-demo-001/inputs/environment/toolchain-set.json <<'JSON'" in runbook_text
    assert '  "toolchain_set_id": "env.toolchains",' in runbook_text
    assert "cat > .belgi/runs/run-demo-001/inputs/environment/tolerances.json <<'JSON'" in runbook_text
    assert '  "tier_id": "tier-1",' in runbook_text
    assert "Then bind them on the same shipped run spine:" in runbook_text
    assert (
        "--toolchain-set-ref env.toolchains=.belgi/runs/run-demo-001/inputs/environment/toolchain-set.json"
        in runbook_text
    )
    assert "--tolerances-ref tier.tolerances=.belgi/runs/run-demo-001/inputs/environment/tolerances.json" in runbook_text
    assert "--toolchain-set-ref <object_id>=<repo-relative-path>" in runbook_text
    assert "--toolchain-ref <object_id>=<repo-relative-path>" in runbook_text
    assert "ToolchainSet is not an Operator Anchor." in runbook_text
    assert "explicit ToolchainSet refs are pre-lock operator inputs." in runbook_text
    assert "Accepted only as the current run canonical input:" in runbook_text
    assert "stages that ToolchainSet into locked/store authority before C1" in runbook_text
    assert (
        "ToolchainSet member declaration paths must still point at actual repo-relative dependency/toolchain declaration surfaces in the evaluated revision truth envelope."
        in runbook_text
    )
    assert "`toolchain.main` is reserved" in runbook_text
    assert "--tolerances-ref <object_id>=<repo-relative-path>" in runbook_text
    assert "Tolerances is not an Operator Anchor." in runbook_text
    assert "explicit Tolerances refs are pre-lock operator inputs." in runbook_text
    assert "stages that Tolerances object into locked/store authority before C1" in runbook_text
    assert "`Tolerances.tier_id` must match the selected tier." in runbook_text
    assert "may equal or tighten the selected tier ceilings, but BELGI rejects wider values" in runbook_text
    assert "generates the canonical Tolerances object from the selected tier pack" in runbook_text
    assert "change only the Tolerances `tier_id` / ceilings so the object stays within that selected tier" in runbook_text
    assert "Artifacts are created under `.belgi/store/runs/<run_key>/<attempt_id>/`." in runbook_text
    assert not tolerances_path.exists()
    assert not toolchain_path.exists()
    assert not (run_dir / "EvidenceManifest.json").exists()
    assert run_key_pointer_path.read_text(encoding="utf-8", errors="strict") == "PENDING\n"
    assert last_attempt_pointer_path.read_text(encoding="utf-8", errors="strict") == "PENDING\n"
    assert open_verdict_pointer_path.read_text(encoding="utf-8", errors="strict") == "PENDING\n"
    assert open_evidence_pointer_path.read_text(encoding="utf-8", errors="strict") == "PENDING\n"

    baseline = {
        "intent": intent_path.read_bytes(),
        "runbook_template": runbook_template_path.read_bytes(),
        "run_key_pointer": run_key_pointer_path.read_bytes(),
        "last_attempt_pointer": last_attempt_pointer_path.read_bytes(),
        "open_verdict_pointer": open_verdict_pointer_path.read_bytes(),
        "open_evidence_pointer": open_evidence_pointer_path.read_bytes(),
    }

    intent_path.write_text("custom-intent\n", encoding="utf-8", errors="strict", newline="\n")
    runbook_template_path.write_text("custom-runbook-template\n", encoding="utf-8", errors="strict", newline="\n")
    tolerances_path.write_text("{\"x\":1}\n", encoding="utf-8", errors="strict", newline="\n")
    toolchain_path.write_text("{\"y\":1}\n", encoding="utf-8", errors="strict", newline="\n")
    run_key_pointer_path.write_text("x\n", encoding="utf-8", errors="strict", newline="\n")
    last_attempt_pointer_path.write_text("y\n", encoding="utf-8", errors="strict", newline="\n")
    open_verdict_pointer_path.write_text("z\n", encoding="utf-8", errors="strict", newline="\n")
    open_evidence_pointer_path.write_text("w\n", encoding="utf-8", errors="strict", newline="\n")
    waiver_path = waivers_dir / "custom-waiver.json"
    waiver_path.write_text("{\"x\":1}\n", encoding="utf-8", errors="strict", newline="\n")

    rc2 = run_belgi(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc2 == 0
    assert intent_path.read_text(encoding="utf-8", errors="strict") == "custom-intent\n"
    assert runbook_template_path.read_text(encoding="utf-8", errors="strict") == "custom-runbook-template\n"
    assert tolerances_path.read_text(encoding="utf-8", errors="strict") == "{\"x\":1}\n"
    assert toolchain_path.read_text(encoding="utf-8", errors="strict") == "{\"y\":1}\n"
    assert run_key_pointer_path.read_text(encoding="utf-8", errors="strict") == "x\n"
    assert last_attempt_pointer_path.read_text(encoding="utf-8", errors="strict") == "y\n"
    assert open_verdict_pointer_path.read_text(encoding="utf-8", errors="strict") == "z\n"
    assert open_evidence_pointer_path.read_text(encoding="utf-8", errors="strict") == "w\n"
    assert waiver_path.read_text(encoding="utf-8", errors="strict") == "{\"x\":1}\n"

    rc3 = run_belgi(["run", "new", "--repo", str(tmp_path), "--run-id", run_id, "--force"])
    assert rc3 == 0
    assert intent_path.read_bytes() == baseline["intent"]
    assert runbook_template_path.read_bytes() == baseline["runbook_template"]
    assert not tolerances_path.exists()
    assert not toolchain_path.exists()
    assert run_key_pointer_path.read_bytes() == baseline["run_key_pointer"]
    assert last_attempt_pointer_path.read_bytes() == baseline["last_attempt_pointer"]
    assert open_verdict_pointer_path.read_bytes() == baseline["open_verdict_pointer"]
    assert open_evidence_pointer_path.read_bytes() == baseline["open_evidence_pointer"]
    assert waiver_path.read_text(encoding="utf-8", errors="strict") == "{\"x\":1}\n"


def test_run_new_layout_no_intentspec_md(tmp_path: Path) -> None:
    assert run_belgi(["init", "--repo", str(tmp_path)]) == 0

    run_id = "run-layout-001"
    rc_new = run_belgi(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc_new == 0

    run_dir = tmp_path / ".belgi" / "runs" / run_id
    assert not (run_dir / "IntentSpec.md").exists()
    assert (run_dir / "inputs" / "intent" / "IntentSpec.core.md").is_file()
    assert (run_dir / "inputs" / "waivers").is_dir()
    assert (run_dir / "inputs" / "anchors" / "approvals").is_dir()
    assert (run_dir / "inputs" / "anchors" / "keys").is_dir()
    assert (run_dir / "inputs" / "anchors" / "signing").is_dir()
    assert (run_dir / "inputs" / "evidence").is_dir()
    assert not (run_dir / "inputs" / "tier2").exists()
    assert not (run_dir / "inputs" / "tier3").exists()
    assert (run_dir / "RUN.md").is_file()
    assert (run_dir / "run_key.txt").is_file()
    assert (run_dir / "last_attempt.txt").is_file()
    assert (run_dir / "open_verdict.txt").is_file()
    assert (run_dir / "open_evidence.txt").is_file()
    assert not (run_dir / "inputs" / "waivers_applied.json").exists()
    assert not (run_dir / "EvidenceManifest.json").exists()


def test_run_new_force_restores_runbook_template(tmp_path: Path) -> None:
    assert run_belgi(["init", "--repo", str(tmp_path)]) == 0

    run_id = "run-layout-force-001"
    run_dir = tmp_path / ".belgi" / "runs" / run_id
    runbook_path = run_dir / "RUN.md"

    rc_new = run_belgi(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc_new == 0
    baseline = runbook_path.read_text(encoding="utf-8", errors="strict")

    runbook_path.write_text("custom-runbook\n", encoding="utf-8", errors="strict", newline="\n")
    rc_force = run_belgi(["run", "new", "--repo", str(tmp_path), "--run-id", run_id, "--force"])
    assert rc_force == 0
    assert runbook_path.read_text(encoding="utf-8", errors="strict") == baseline
