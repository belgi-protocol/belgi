from __future__ import annotations

"""Repo-local synthetic payload builders for tests only.

This module is not shipped runtime or tooling authority.
It exists only to construct deterministic test inputs.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent
BUILTIN_PACK_ROOT = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
MANIFEST_FILENAME = "ProtocolPackManifest.json"

__all__ = [
    "build_q_repo",
    "build_r_repo",
    "build_s_repo",
    "builtin_tiers",
    "copy_builtin_protocol_pack",
    "init_git_repo",
    "object_ref",
    "read_json",
    "run_gate_q",
    "run_gate_r",
    "structured_command",
    "sync_locked_spec_protocol_identity",
    "tier_contract",
    "write_bytes",
    "write_json",
    "write_text",
    "write_tiers_override",
]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(obj, dict)
    return obj


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="strict", newline="\n")


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def object_ref(storage_ref: str, data: bytes, object_id: str) -> dict[str, str]:
    return {
        "id": object_id,
        "hash": sha256_hex(data),
        "storage_ref": storage_ref,
    }


def copy_builtin_protocol_pack(repo_root: Path) -> Path:
    pack_root = repo_root / "protocol_pack"
    shutil.copytree(BUILTIN_PACK_ROOT, pack_root, dirs_exist_ok=True)
    return pack_root


def sync_locked_spec_protocol_identity(locked_path: Path, manifest_path: Path) -> None:
    locked = read_json(locked_path)
    manifest = read_json(manifest_path)
    protocol_pack = dict(locked.get("protocol_pack") or {})
    protocol_pack["pack_id"] = manifest["pack_id"]
    protocol_pack["manifest_sha256"] = sha256_hex(manifest_path.read_bytes())
    protocol_pack["pack_name"] = manifest["pack_name"]
    protocol_pack["source"] = "builtin"
    locked["protocol_pack"] = protocol_pack
    write_json(locked_path, locked)


def builtin_tiers() -> dict[str, Any]:
    return read_json(REPO_ROOT / "tiers" / "tier-packs.json")


def tier_contract(tier_id: str, *, tiers_obj: dict[str, Any] | None = None) -> dict[str, Any]:
    tiers_source = builtin_tiers() if tiers_obj is None else tiers_obj
    tiers = tiers_source.get("tiers")
    assert isinstance(tiers, dict), "tiers/tier-packs.json missing tiers map"
    contract = tiers.get(tier_id)
    assert isinstance(contract, dict), f"missing tier contract for {tier_id}"
    return contract


def write_tiers_override(repo_root: Path, tiers_obj: dict[str, Any]) -> str:
    rel = "tiers.override.json"
    write_json(repo_root / rel, tiers_obj)
    return rel


def _sync_repo_locked_specs_upstream_commit(repo_root: Path, commit_sha: str) -> None:
    for locked_path in sorted(repo_root.rglob("LockedSpec.json"), key=lambda path: path.as_posix()):
        try:
            locked = read_json(locked_path)
        except Exception:
            continue
        upstream_state = locked.get("upstream_state")
        if upstream_state is None:
            upstream_state = {}
        if not isinstance(upstream_state, dict):
            continue
        upstream_state["commit_sha"] = commit_sha
        locked["upstream_state"] = upstream_state
        write_json(locked_path, locked)


def _install_synthetic_gitignore(repo_root: Path) -> None:
    write_text(
        repo_root / ".gitignore",
        "\n".join(
            [
                "gate_q/",
                "gate_r/",
                "inputs/",
                "synthetic/",
                "out/",
                "protocol_pack/",
                "belgi_pack/",
                "tiers.override.json",
                "",
            ]
        ),
    )


def _apply_synthetic_repo_diff_targets(repo_root: Path) -> None:
    for diff_path in sorted(repo_root.rglob("repo.diff.patch"), key=lambda path: path.as_posix()):
        text = diff_path.read_text(encoding="utf-8", errors="strict")
        current_rel: str | None = None
        added_lines: list[str] = []

        def flush() -> None:
            if current_rel is None:
                return
            final_bytes = ("\n".join(added_lines) + "\n").encode("utf-8", errors="strict")
            write_bytes(repo_root / Path(*current_rel.split("/")), final_bytes)

        for line in text.splitlines():
            if line.startswith("diff --git "):
                flush()
                parts = line.split()
                if len(parts) < 4:
                    raise AssertionError(f"unexpected synthetic diff header: {line}")
                old_rel = parts[2].removeprefix("a/")
                new_rel = parts[3].removeprefix("b/")
                if old_rel != new_rel:
                    raise AssertionError(f"synthetic rename diff not supported: {line}")
                current_rel = new_rel
                added_lines = []
                continue
            if line.startswith("+++ ") or line.startswith("--- ") or line.startswith("@@"):
                continue
            if line.startswith("+"):
                added_lines.append(line[1:])

        flush()


def structured_command(subcommand: str, *, exit_code: int = 0) -> dict[str, Any]:
    return {
        "argv": ["belgi", subcommand],
        "exit_code": exit_code,
        "started_at": "1970-01-01T00:00:00Z",
        "finished_at": "1970-01-01T00:00:00Z",
    }


def _intent_scope_string(allowed_dirs: list[str], forbidden_dirs: list[str]) -> str:
    return f"allowed_dirs: [{', '.join(allowed_dirs)}]; forbidden_dirs: [{', '.join(forbidden_dirs)}]"


def _intent_success_criteria(success_criteria: list[str]) -> str:
    return "\n".join(f"- {item}" for item in success_criteria)


def _tier_name_for(tier_id: str) -> str:
    suffix = tier_id.removeprefix("tier-")
    if suffix.isdigit():
        return f"Tier {suffix}"
    return f"Tier {tier_id}"


def _render_yaml_list(items: list[str], *, indent: str) -> str:
    if not items:
        return " []"
    return "\n" + "\n".join(f'{indent}- "{item}"' for item in items)


def build_q_repo(
    repo_root: Path,
    *,
    rel_root: str = "inputs/q",
    tier_id: str = "tier-0",
    tiers_obj: dict[str, Any] | None = None,
    run_id: str = "q-pass",
    allowed_dirs: list[str] | None = None,
    forbidden_dirs: list[str] | None = None,
    success_criteria: list[str] | None = None,
    doc_impact: dict[str, Any] | None = None,
    invariants: list[dict[str, Any]] | None = None,
    allowed_repo_refs: list[str] | None = None,
    prompt_storage_ref: str | None = "prompt_bundle.txt",
    publication_intent: dict[str, Any] | None = None,
    waivers_applied: list[str] | None = None,
    extra_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    if tiers_obj is None:
        tiers_obj = builtin_tiers()
    contract = tier_contract(tier_id, tiers_obj=tiers_obj)
    allowed_dirs = ["policy/"] if allowed_dirs is None else list(allowed_dirs)
    forbidden_dirs = [] if forbidden_dirs is None else list(forbidden_dirs)
    success_criteria = ["Criterion 1"] if success_criteria is None else list(success_criteria)
    if doc_impact is None:
        doc_impact = {
            "required_paths": [],
            "note_on_empty": "No documentation update required for this synthetic case.",
        }
    invariants = list(
        [
            {
                "id": "INV-001",
                "description": "synthetic invariant",
                "severity": "policy",
            }
        ]
        if invariants is None
        else invariants
    )
    waivers_applied = [] if waivers_applied is None else list(waivers_applied)

    pack_root = copy_builtin_protocol_pack(repo_root)
    manifest_path = pack_root / MANIFEST_FILENAME

    prompt_rel = f"{rel_root}/prompt_bundle.txt" if prompt_storage_ref is None else prompt_storage_ref
    prompt_path = repo_root / Path(*prompt_rel.split("/"))
    prompt_bytes = b"synthetic prompt bundle\n"
    write_bytes(prompt_path, prompt_bytes)

    toolchain_set_rel = f"{rel_root}/toolchain-set.json"
    toolchain_set_path = repo_root / toolchain_set_rel
    toolchain_set_obj = {
        "schema_version": "1.0.0",
        "toolchain_set_id": "env.toolchains",
        "refs": [],
    }
    write_json(toolchain_set_path, toolchain_set_obj)

    tolerances_rel = f"{rel_root}/tolerances.json"
    tolerances_path = repo_root / tolerances_rel
    write_json(
        tolerances_path,
        {
            "schema_version": "1.0.0",
            "tier_id": tier_id,
            "scope_budgets": {
                "max_touched_files": contract["scope_budgets"]["max_touched_files"],
                "max_loc_delta": contract["scope_budgets"]["max_loc_delta"],
            },
        },
    )

    intent_rel = f"{rel_root}/IntentSpec.core.md"
    locked_rel = f"{rel_root}/LockedSpec.json"
    evidence_rel = f"{rel_root}/EvidenceManifest.json"
    attestation_pubkey_ref: dict[str, str] | None = None
    seal_pubkey_ref: dict[str, str] | None = None

    if tier_id in {"tier-2", "tier-3"}:
        attestation_pubkey_rel = f"{rel_root}/attestation_pubkey.hex"
        seal_pubkey_rel = f"{rel_root}/seal_pubkey.hex"
        attestation_pubkey_bytes = (("1" * 64) + "\n").encode("utf-8", errors="strict")
        seal_pubkey_bytes = (("2" * 64) + "\n").encode("utf-8", errors="strict")
        write_bytes(repo_root / attestation_pubkey_rel, attestation_pubkey_bytes)
        write_bytes(repo_root / seal_pubkey_rel, seal_pubkey_bytes)
        attestation_pubkey_ref = object_ref(attestation_pubkey_rel, attestation_pubkey_bytes, "env.attestation_pubkey")
        seal_pubkey_ref = object_ref(seal_pubkey_rel, seal_pubkey_bytes, "env.seal_pubkey")

    intent_obj: dict[str, Any] = {
        "intent_id": f"intent-{run_id}",
        "title": "Synthetic intent",
        "goal": "Exercise synthetic Gate Q coverage.",
        "scope": {
            "allowed_dirs": allowed_dirs,
            "forbidden_dirs": forbidden_dirs,
        },
        "acceptance": {
            "success_criteria": success_criteria,
        },
        "tier": {
            "tier_pack_id": tier_id,
        },
    }
    intent_obj["doc_impact"] = doc_impact
    if publication_intent is not None:
        intent_obj["publication_intent"] = publication_intent

    intent_text = (
        "# Intent\n```yaml\n"
        f'intent_id: "{intent_obj["intent_id"]}"\n'
        f'title: "{intent_obj["title"]}"\n'
        f'goal: "{intent_obj["goal"]}"\n'
        "scope:\n"
        f"  allowed_dirs:{_render_yaml_list(allowed_dirs, indent='    ')}\n"
        f"  forbidden_dirs:{_render_yaml_list(forbidden_dirs, indent='    ')}\n"
        "acceptance:\n"
        f"  success_criteria:{_render_yaml_list(success_criteria, indent='    ')}"
    )
    intent_text += f'\ntier:\n  tier_pack_id: "{tier_id}"'
    required_paths = doc_impact.get("required_paths", [])
    intent_text += "\ndoc_impact:\n  required_paths:"
    if required_paths:
        intent_text += "\n" + "\n".join(f'    - "{item}"' for item in required_paths)
    else:
        intent_text += " []"
    note = doc_impact.get("note_on_empty")
    if note is not None:
        intent_text += f'\n  note_on_empty: "{note}"'
    if publication_intent is not None:
        intent_text += (
            "\npublication_intent:\n"
            f'  publish: {"true" if publication_intent.get("publish") else "false"}\n'
            f'  profile: "{publication_intent.get("profile", "public")}"'
        )
    intent_text += "\n```\n"
    write_text(repo_root / intent_rel, intent_text)

    environment_envelope: dict[str, Any] = {
        "id": "env.synthetic",
        "description": "synthetic envelope",
        "expected_runner": "ci:synthetic",
        "toolchain_set_ref": object_ref(toolchain_set_rel, toolchain_set_path.read_bytes(), "env.toolchains"),
        "pinned_toolchain_refs": [
            {
                "id": "toolchain.main",
                "hash": "0" * 64,
                "storage_ref": "out/inputs/toolchain.json",
            }
        ],
    }
    if attestation_pubkey_ref is not None:
        environment_envelope["attestation_pubkey_ref"] = attestation_pubkey_ref
    if seal_pubkey_ref is not None:
        environment_envelope["seal_pubkey_ref"] = seal_pubkey_ref

    locked_spec: dict[str, Any] = {
        "schema_version": "1.0.0",
        "belgi_version": "1.6.0",
        "run_id": run_id,
        "compilation": {
            "compiled_at": "1970-01-01T00:00:00Z",
            "compiler_id": "C1",
            "compiler_version": "synthetic",
            "source_hashes": ["0" * 64],
        },
        "intent": {
            "intent_id": intent_obj["intent_id"],
            "title": intent_obj["title"],
            "narrative": intent_obj["goal"],
            "scope": _intent_scope_string(allowed_dirs, forbidden_dirs),
            "success_criteria": _intent_success_criteria(success_criteria),
        },
        "constraints": {
            "allowed_paths": allowed_dirs,
            "forbidden_paths": forbidden_dirs,
        },
        "invariants": invariants,
        "tier": {
            "tier_id": tier_id,
            "tier_name": _tier_name_for(tier_id),
            "tolerances_ref": object_ref(tolerances_rel, tolerances_path.read_bytes(), "tier.tolerances"),
        },
        "environment_envelope": environment_envelope,
        "prompt_bundle_ref": object_ref(prompt_rel, prompt_bytes, "prompt.bundle"),
        "protocol_pack": {
            "pack_id": "0" * 64,
            "manifest_sha256": "0" * 64,
            "pack_name": "placeholder",
            "source": "builtin",
        },
        "upstream_state": {
            "commit_sha": "0" * 40,
            "dirty_flag": False,
            "repo_ref": "synthetic",
        },
        "waivers_applied": waivers_applied,
    }
    locked_spec["doc_impact"] = doc_impact
    if allowed_repo_refs is not None:
        locked_spec["allowed_repo_refs"] = allowed_repo_refs
    if publication_intent is not None:
        locked_spec["publication_intent"] = publication_intent
    write_json(repo_root / locked_rel, locked_spec)
    sync_locked_spec_protocol_identity(repo_root / locked_rel, manifest_path)

    command_log_rel = f"{rel_root}/command.log.txt"
    policy_report_rel = f"{rel_root}/policy.report.json"
    schema_validation_rel = f"{rel_root}/schema.validation.json"
    write_text(repo_root / command_log_rel, "synthetic command log\n")
    write_json(repo_root / policy_report_rel, {"schema_version": "1.0.0", "kind": "synthetic"})
    write_json(repo_root / schema_validation_rel, {"schema_version": "1.0.0", "valid": True})

    artifacts = [
        {
            "kind": "command_log",
            "id": "command.log",
            "hash": sha256_hex((repo_root / command_log_rel).read_bytes()),
            "media_type": "text/plain",
            "produced_by": "C1",
            "storage_ref": command_log_rel,
        },
        {
            "kind": "policy_report",
            "id": "policy.report",
            "hash": sha256_hex((repo_root / policy_report_rel).read_bytes()),
            "media_type": "application/json",
            "produced_by": "C1",
            "storage_ref": policy_report_rel,
        },
        {
            "kind": "schema_validation",
            "id": "schema.validation",
            "hash": sha256_hex((repo_root / schema_validation_rel).read_bytes()),
            "media_type": "application/json",
            "produced_by": "C1",
            "storage_ref": schema_validation_rel,
        },
    ]
    if extra_artifacts:
        artifacts.extend(extra_artifacts)
    write_json(
        repo_root / evidence_rel,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "artifacts": artifacts,
            "commands_executed": ["belgi c1-compile"],
            "envelope_attestation": None,
        },
    )
    return {
        "intent": intent_rel,
        "locked": locked_rel,
        "evidence": evidence_rel,
        "toolchain_set": toolchain_set_rel,
        "tolerances": tolerances_rel,
        "protocol_pack": "protocol_pack",
    }


def build_r_repo(
    repo_root: Path,
    *,
    rel_root: str = "inputs/r",
    tier_id: str = "tier-1",
    tiers_obj: dict[str, Any] | None = None,
    run_id: str = "r-pass",
    doc_impact: dict[str, Any] | None = None,
    diff_paths: list[str] | None = None,
) -> dict[str, str]:
    if tiers_obj is None:
        tiers_obj = builtin_tiers()
    contract = tier_contract(tier_id, tiers_obj=tiers_obj)
    q_paths = build_q_repo(
        repo_root,
        rel_root=rel_root,
        tier_id=tier_id,
        tiers_obj=tiers_obj,
        run_id=run_id,
        allowed_dirs=["src/"],
        forbidden_dirs=[],
        success_criteria=["R path passes"],
        doc_impact=doc_impact,
    )
    locked_rel = q_paths["locked"]
    evidence_rel = q_paths["evidence"]
    locked_path = repo_root / locked_rel
    evidence_path = repo_root / evidence_rel

    diff_paths = ["src/changed.py"] if diff_paths is None else list(diff_paths)
    diff_rel = f"{rel_root}/repo.diff.patch"
    diff_lines = []
    for changed in diff_paths:
        write_text(repo_root / Path(*changed.split("/")), "old\n")
        diff_lines.extend(
            [
                f"diff --git a/{changed} b/{changed}",
                f"--- a/{changed}",
                f"+++ b/{changed}",
                "@@ -1 +1 @@",
                "-old",
                "+new",
            ]
        )
    write_text(repo_root / diff_rel, "\n".join(diff_lines) + "\n")

    command_log_rel = f"{rel_root}/command.log.json"
    command_log_bytes = json.dumps(
        [structured_command("invariant-eval"), structured_command("run-tests"), structured_command("verify-attestation"), structured_command("supplychain-scan"), structured_command("adversarial-scan")],
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    write_bytes(repo_root / command_log_rel, command_log_bytes)

    policy_invariant_rel = f"{rel_root}/policy.invariant_eval.json"
    policy_supply_rel = f"{rel_root}/policy.supplychain.json"
    policy_adv_rel = f"{rel_root}/policy.adversarial_scan.json"
    test_report_rel = f"{rel_root}/tests.report.json"
    schema_validation_rel = f"{rel_root}/schema.validation.json"
    env_attestation_rel = f"{rel_root}/env_attestation.json"

    write_json(
        repo_root / policy_invariant_rel,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "generated_at": "1970-01-01T00:00:00Z",
            "summary": {"total_checks": 1, "passed": 1, "failed": 0},
            "checks": [{"check_id": "policy.invariant_eval", "passed": True, "message": "synthetic"}],
        },
    )
    write_json(
        repo_root / policy_supply_rel,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "generated_at": "1970-01-01T00:00:00Z",
            "summary": {"total_checks": 1, "passed": 1, "failed": 0},
            "checks": [{"check_id": "policy.supplychain", "passed": True, "message": "synthetic"}],
            "declared_toolchain_refs": ["out/inputs/toolchain.json"],
            "relevant_changed_paths": [],
            "unaccounted_paths": [],
        },
    )
    write_json(
        repo_root / policy_adv_rel,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "generated_at": "1970-01-01T00:00:00Z",
            "summary": {"total_checks": 1, "passed": 1, "failed": 0},
            "checks": [{"check_id": "policy.adversarial_scan", "passed": True, "message": "synthetic"}],
            "findings": [],
        },
    )
    write_json(
        repo_root / test_report_rel,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "generated_at": "1970-01-01T00:00:00Z",
            "summary": {"total": 1, "passed": 1, "failed": 0, "skipped": 0, "duration_seconds": 0.0},
        },
    )
    write_json(repo_root / schema_validation_rel, {"schema_version": "1.0.0", "run_id": run_id, "valid": True})
    write_json(
        repo_root / env_attestation_rel,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "attestation_id": "env.attestation",
            "generated_at": "1970-01-01T00:00:00Z",
            "command_log_sha256": sha256_hex(command_log_bytes),
        },
    )

    write_json(
        evidence_path,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "artifacts": [
                {
                    "kind": "diff",
                    "id": "repo.diff",
                    "hash": sha256_hex((repo_root / diff_rel).read_bytes()),
                    "media_type": "text/x-diff",
                    "produced_by": "C2",
                    "storage_ref": diff_rel,
                },
                {
                    "kind": "policy_report",
                    "id": "policy.invariant_eval",
                    "hash": sha256_hex((repo_root / policy_invariant_rel).read_bytes()),
                    "media_type": "application/json",
                    "produced_by": "C1",
                    "storage_ref": policy_invariant_rel,
                },
                {
                    "kind": "policy_report",
                    "id": "policy.supplychain",
                    "hash": sha256_hex((repo_root / policy_supply_rel).read_bytes()),
                    "media_type": "application/json",
                    "produced_by": "C1",
                    "storage_ref": policy_supply_rel,
                },
                {
                    "kind": "policy_report",
                    "id": "policy.adversarial_scan",
                    "hash": sha256_hex((repo_root / policy_adv_rel).read_bytes()),
                    "media_type": "application/json",
                    "produced_by": "C1",
                    "storage_ref": policy_adv_rel,
                },
                {
                    "kind": "test_report",
                    "id": "tests.report",
                    "hash": sha256_hex((repo_root / test_report_rel).read_bytes()),
                    "media_type": "application/json",
                    "produced_by": "C1",
                    "storage_ref": test_report_rel,
                },
                {
                    "kind": "command_log",
                    "id": "command.log",
                    "hash": sha256_hex(command_log_bytes),
                    "media_type": "application/json",
                    "produced_by": "C1",
                    "storage_ref": command_log_rel,
                },
                {
                    "kind": "schema_validation",
                    "id": "schema.validation",
                    "hash": sha256_hex((repo_root / schema_validation_rel).read_bytes()),
                    "media_type": "application/json",
                    "produced_by": "R",
                    "storage_ref": schema_validation_rel,
                },
                {
                    "kind": "env_attestation",
                    "id": "env.attestation",
                    "hash": sha256_hex((repo_root / env_attestation_rel).read_bytes()),
                    "media_type": "application/json",
                    "produced_by": "C1",
                    "storage_ref": env_attestation_rel,
                },
            ],
            "commands_executed": [
                structured_command("invariant-eval"),
                structured_command("run-tests"),
                structured_command("verify-attestation"),
                structured_command("supplychain-scan"),
                structured_command("adversarial-scan"),
            ],
            "envelope_attestation": object_ref(env_attestation_rel, (repo_root / env_attestation_rel).read_bytes(), "env.attestation"),
        },
    )

    gate_q_rel = f"{rel_root}/GateVerdict.Q.json"
    write_json(
        repo_root / gate_q_rel,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "gate_id": "Q",
            "verdict": "GO",
            "failure_category": None,
            "failures": [],
            "evidence_manifest_ref": object_ref(evidence_rel, evidence_path.read_bytes(), "evidence"),
            "evaluated_at": "1970-01-01T00:00:00Z",
            "evaluator": "synthetic",
        },
    )

    # Align tier-specific command-log mode expectations.
    if contract["command_log_mode"] == "strings":
        evidence = read_json(evidence_path)
        evidence["commands_executed"] = [
            "belgi invariant-eval",
            "belgi run-tests",
            "belgi verify-attestation",
            "belgi supplychain-scan",
            "belgi adversarial-scan",
        ]
        write_json(evidence_path, evidence)

    sync_locked_spec_protocol_identity(locked_path, repo_root / "protocol_pack" / MANIFEST_FILENAME)
    return {
        "locked": locked_rel,
        "evidence": evidence_rel,
        "gate_q_verdict": gate_q_rel,
        "protocol_pack": "protocol_pack",
    }


def build_s_repo(
    repo_root: Path,
    *,
    rel_root: str = "inputs/s",
    run_id: str = "s-pass",
    include_signature: bool = False,
    signature: str | None = None,
) -> dict[str, str]:
    pack_root = copy_builtin_protocol_pack(repo_root)
    r_paths = build_r_repo(repo_root, rel_root=rel_root, run_id=run_id)
    locked_rel = r_paths["locked"]
    evidence_rel = r_paths["evidence"]
    gate_q_rel = r_paths["gate_q_verdict"]
    gate_r_rel = f"{rel_root}/GateVerdict.R.json"
    snapshot_rel = "out/EvidenceManifest.r_snapshot.json"
    snapshot_bytes = (repo_root / evidence_rel).read_bytes()
    write_bytes(repo_root / snapshot_rel, snapshot_bytes)
    write_json(
        repo_root / gate_r_rel,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "gate_id": "R",
            "verdict": "GO",
            "failure_category": None,
            "failures": [],
            "evidence_manifest_ref": object_ref(snapshot_rel, snapshot_bytes, "evidence.r"),
            "evaluated_at": "1970-01-01T00:00:00Z",
            "evaluator": "synthetic",
        },
    )
    seal_rel = f"{rel_root}/SealManifest.json"
    cmd = [
        sys.executable,
        "-m",
        "chain.seal_bundle",
        "--repo",
        str(repo_root),
        "--locked-spec",
        locked_rel,
        "--gate-q-verdict",
        gate_q_rel,
        "--gate-r-verdict",
        gate_r_rel,
        "--evidence-manifest",
        evidence_rel,
        "--final-commit-sha",
        "0" * 40,
        "--sealed-at",
        "1970-01-01T00:00:00Z",
        "--signer",
        "human:synthetic@example.com",
        "--out",
        seal_rel,
    ]
    if include_signature:
        sig_rel = f"{rel_root}/seal.signature.txt"
        write_text(repo_root / sig_rel, ("AA==" if signature is None else signature) + "\n")
        cmd.extend(["--seal-signature-ref", sig_rel])
    cp = subprocess.run(cmd, cwd=str(REPO_ROOT), check=False, capture_output=True, text=True)
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    assert (repo_root / seal_rel).exists(), seal_rel
    sync_locked_spec_protocol_identity(repo_root / locked_rel, pack_root / MANIFEST_FILENAME)
    return {
        "locked": locked_rel,
        "evidence": evidence_rel,
        "gate_q_verdict": gate_q_rel,
        "gate_r_verdict": gate_r_rel,
        "seal": seal_rel,
        "protocol_pack": "protocol_pack",
    }


def run_gate_q(
    repo_root: Path,
    *,
    intent_rel: str,
    locked_rel: str,
    evidence_rel: str,
    out_rel: str = "out/GateVerdict.Q.json",
    tiers_rel: str | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if tiers_rel is not None:
        env["BELGI_DEV"] = "1"
        env.pop("CI", None)
    cmd = [
        sys.executable,
        "-m",
        "chain.gate_q_verify",
        "--repo",
        str(repo_root),
        "--protocol-pack",
        "protocol_pack",
        "--intent-spec",
        intent_rel,
        "--locked-spec",
        locked_rel,
        "--evidence-manifest",
        evidence_rel,
        "--out",
        out_rel,
    ]
    if tiers_rel is not None:
        cmd.extend(["--tiers", tiers_rel])
    return subprocess.run(cmd, cwd=str(REPO_ROOT), check=False, capture_output=True, text=True, env=env)


def run_gate_r(
    repo_root: Path,
    *,
    locked_rel: str,
    gate_q_rel: str,
    evidence_rel: str,
    evaluated_revision: str,
    verify_rel: str = "out/verify_report.json",
    verdict_rel: str = "out/GateVerdict.R.json",
    snapshot_rel: str = "out/EvidenceManifest.r_snapshot.json",
    tiers_rel: str | None = None,
    overlay_rel: str | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if tiers_rel is not None:
        env["BELGI_DEV"] = "1"
        env.pop("CI", None)
    cmd = [
        sys.executable,
        "-m",
        "chain.gate_r_verify",
        "--repo",
        str(repo_root),
        "--protocol-pack",
        "protocol_pack",
        "--locked-spec",
        locked_rel,
        "--gate-q-verdict",
        gate_q_rel,
        "--evidence-manifest",
        evidence_rel,
        "--r-snapshot-manifest-out",
        snapshot_rel,
        "--evaluated-revision",
        evaluated_revision,
        "--out",
        verify_rel,
        "--gate-verdict-out",
        verdict_rel,
    ]
    if tiers_rel is not None:
        cmd.extend(["--tiers", tiers_rel])
    if overlay_rel is not None:
        cmd.extend(["--overlay", overlay_rel])
    return subprocess.run(cmd, cwd=str(REPO_ROOT), check=False, capture_output=True, text=True, env=env)


def init_git_repo(repo_root: Path) -> str:
    """Create a synthetic repo and return the final clean HEAD under test.

    The returned revision is the exact committed state that positive Gate R
    tests must evaluate. Synthetic inputs remain off the tracked git surface;
    the git diff under test is produced only by committed repo bytes.
    """

    git_env = os.environ.copy()
    git_env["GIT_AUTHOR_DATE"] = "1970-01-01T00:00:00Z"
    git_env["GIT_COMMITTER_DATE"] = "1970-01-01T00:00:00Z"

    def git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=str(repo_root),
            check=True,
            capture_output=True,
            text=True,
            env=git_env,
        )

    git("init")
    git("config", "user.email", "ci@example.invalid")
    git("config", "user.name", "ci")
    git("config", "core.autocrlf", "false")
    _install_synthetic_gitignore(repo_root)
    git("add", "-A")
    git("commit", "--allow-empty", "-m", "synthetic-base")
    upstream_commit_sha = git("rev-parse", "HEAD").stdout.strip()

    _sync_repo_locked_specs_upstream_commit(repo_root, upstream_commit_sha)
    _apply_synthetic_repo_diff_targets(repo_root)
    git("add", "-A")

    if git("status", "--porcelain").stdout.strip():
        git("commit", "--allow-empty", "-m", "synthetic-evaluated")

    final_head = git("rev-parse", "HEAD").stdout.strip()
    dirty = git("status", "--porcelain").stdout.strip()
    assert final_head, "synthetic repo HEAD missing after initialization"
    assert not dirty, f"synthetic repo must be clean after initialization: {dirty}"
    return final_head
