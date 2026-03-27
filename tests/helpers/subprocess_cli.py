from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _ensure_repo_root_on_syspath() -> None:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))


def clear_base_revision_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BELGI_BASE_SHA", raising=False)
    monkeypatch.delenv("GITHUB_BASE_SHA", raising=False)


def _child_env(env_overrides: dict[str, str | None] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("BELGI_BASE_SHA", None)
    env.pop("GITHUB_BASE_SHA", None)
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(REPO_ROOT)
        if not existing_pythonpath
        else os.pathsep.join((str(REPO_ROOT), existing_pythonpath))
    )
    if env_overrides:
        for key, value in env_overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
    return env


def run_belgi(args: list[str], *, env_overrides: dict[str, str | None] | None = None) -> int:
    cp = subprocess.run(
        [sys.executable, "-m", "belgi.cli", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
        env=_child_env(env_overrides),
    )
    sys.stdout.write(cp.stdout)
    sys.stderr.write(cp.stderr)
    return cp.returncode


def current_platform_family() -> str:
    if sys.platform.startswith("darwin"):
        return "macos"
    if os.name == "nt" or sys.platform.startswith("win"):
        return "windows"
    return "linux"


def current_open_label() -> str:
    return f"open_{current_platform_family()}:"


def other_open_labels() -> list[str]:
    current = current_platform_family()
    return [f"open_{name}:" for name in ("linux", "macos", "windows") if name != current]


def validate_schema(instance: object, schema: object, *, root_schema: object, path: str) -> list[object]:
    _ensure_repo_root_on_syspath()
    from belgi.core.schema import validate_schema as _validate_schema

    return _validate_schema(instance, schema, root_schema=root_schema, path=path)


def get_builtin_protocol_context():
    _ensure_repo_root_on_syspath()
    from belgi.protocol.pack import (
        get_builtin_protocol_context as _get_builtin_protocol_context,
    )

    return _get_builtin_protocol_context()


def load_pinned_trust_anchor(repo_root: Path):
    _ensure_repo_root_on_syspath()
    from belgi.trust_anchor import load_pinned_trust_anchor as _load_pinned_trust_anchor

    return _load_pinned_trust_anchor(repo_root)


def _list_dirs(path: Path) -> list[Path]:
    return sorted([p for p in path.iterdir() if p.is_dir()], key=lambda p: p.name)


def _fresh_repo_clone(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    cp = subprocess.run(
        ["git", "clone", "--quiet", "--shared", str(REPO_ROOT), str(repo)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr
    cp_cfg_email = subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp_cfg_email.returncode == 0, cp_cfg_email.stderr
    cp_cfg_name = subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp_cfg_name.returncode == 0, cp_cfg_name.stderr
    return repo


def _commit_file(repo: Path, rel: str, content: str, msg: str) -> None:
    path = repo / Path(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="strict")
    cp_add = subprocess.run(
        ["git", "-C", str(repo), "add", rel],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp_add.returncode == 0, cp_add.stderr
    cp_commit = subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", msg],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp_commit.returncode == 0, cp_commit.stderr


def _write_tolerances_object(
    repo: Path,
    rel: str,
    *,
    tier_id: str,
    max_touched_files: int | None,
    max_loc_delta: int | None,
    msg: str,
) -> None:
    payload = {
        "schema_version": "1.0.0",
        "tier_id": tier_id,
        "scope_budgets": {
            "max_touched_files": max_touched_files,
            "max_loc_delta": max_loc_delta,
        },
    }
    _commit_file(
        repo,
        rel,
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        msg,
    )


def _write_toolchain_set_object(
    repo: Path,
    rel: str,
    *,
    toolchain_set_id: str,
    refs: list[dict[str, str]],
    msg: str,
) -> None:
    payload = {
        "schema_version": "1.0.0",
        "toolchain_set_id": toolchain_set_id,
        "refs": refs,
    }
    _commit_file(
        repo,
        rel,
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        msg,
    )


def _write_local_json_object(repo: Path, rel: str, payload: object) -> None:
    path = repo / Path(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
    )


def _run_git(repo: Path, args: list[str]) -> None:
    cp = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr


def _git_rev_parse(repo: Path, revision: str) -> str:
    cp = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", revision],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr
    sha = cp.stdout.strip().lower()
    assert re.fullmatch(r"[0-9a-f]{40}", sha)
    return sha


def _unset_upstream_if_present(repo: Path) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "branch", "--unset-upstream"],
        capture_output=True,
        text=True,
        check=False,
    )


def _extract_run_human_block(stderr: str, *, level: str = "NO-GO") -> list[str]:
    lines = stderr.splitlines()
    start = -1
    for idx, line in enumerate(lines):
        if line.startswith(f"[belgi run] {level}:"):
            start = idx
            break
    if start < 0:
        return []
    out: list[str] = []
    for line in lines[start:]:
        if line and not line.startswith("[belgi run]"):
            break
        out.append(line)
    return out


def _open_target_labels(stderr: str) -> list[str]:
    labels: list[str] = []
    in_open = False
    for line in stderr.splitlines():
        if line == "[belgi run] open:":
            in_open = True
            continue
        if not in_open:
            continue
        if line == "":
            continue
        if line.startswith("[belgi run] details:"):
            break
        m = re.match(r"^\[belgi run\] {3}(?!open_)([^ :][^:]*):", line)
        if m is not None:
            labels.append(str(m.group(1)))
    return labels


def _remove_tests_tree_and_commit(repo: Path) -> None:
    _run_git(repo, ["rm", "-r", "--quiet", "--ignore-unmatch", "tests"])
    _run_git(repo, ["commit", "-m", "remove tests tree"])


def _write_applied_waiver(
    repo: Path,
    *,
    file_name: str,
    rule_id: str,
    scope_path: str,
    expires_at: str,
) -> Path:
    waivers_dir = repo / ".belgi" / "waivers_applied"
    waivers_dir.mkdir(parents=True, exist_ok=True)
    waiver_path = waivers_dir / file_name
    waiver_doc = {
        "schema_version": "1.0.0",
        "waiver_id": "waiver-tier1-r8",
        "gate_id": "R",
        "rule_id": rule_id,
        "scope": f"path:{scope_path}",
        "justification": "Deterministic waiver for tier-1 integration test.",
        "mitigation": "Follow-up patch removes risky primitive.",
        "approver": "human:test@example.com",
        "created_at": "1970-01-01T00:00:00Z",
        "expires_at": expires_at,
        "audit_trail_ref": {"id": "audit-001", "storage_ref": "waivers/audit.log"},
        "status": "active",
    }
    waiver_path.write_text(
        json.dumps(waiver_doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
    )
    return waiver_path


def _ed25519_pubkey_hex(seed_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return public_key.hex()


def _rewrite_shared_run_intent_for_empty_doc_impact(
    repo: Path,
    *,
    run_id: str,
    note: str,
    tier_id: str = "tier-2",
    allowed_dirs: list[str] | None = None,
) -> Path:
    def _render_yaml_list(items: list[str]) -> str:
        if not items:
            return " []"
        return "\n" + "\n".join(f'    - "{item}"' for item in items)

    intent_path = repo / ".belgi" / "runs" / run_id / "inputs" / "intent" / "IntentSpec.core.md"
    text = intent_path.read_text(encoding="utf-8", errors="strict")
    updated, tier_count = re.subn(
        r'tier:\n  tier_pack_id: "[^"]+"\n',
        f"tier:\n  tier_pack_id: {json.dumps(tier_id)}\n",
        text,
        count=1,
    )
    assert tier_count == 1
    updated, doc_count = re.subn(
        r'(?ms)^doc_impact:\n  required_paths:(?: \[\]|(?:\n(?: {4}- "[^\n]*"\n?)+))\n  note_on_empty: "[^\n]*"\n?',
        "doc_impact:\n"
        "  required_paths: []\n"
        f"  note_on_empty: {json.dumps(note)}\n",
        updated,
        count=1,
    )
    assert doc_count == 1
    if allowed_dirs is not None:
        updated, allowed_count = re.subn(
            r'(?m)^  allowed_dirs:(?: \[\]|(?:\n(?: {4}- "[^\n]*"\n?)+))',
            "  allowed_dirs:" + _render_yaml_list(list(allowed_dirs)),
            updated,
            count=1,
        )
        assert allowed_count == 1
    assert updated != text
    intent_path.write_text(updated, encoding="utf-8", errors="strict", newline="\n")
    return intent_path


def _write_operator_anchors(repo: Path, *, run_id: str) -> dict[str, str]:
    anchors_dir = repo / ".belgi" / "runs" / run_id / "inputs" / "anchors"
    approvals_dir = anchors_dir / "approvals"
    keys_dir = anchors_dir / "keys"
    signing_dir = anchors_dir / "signing"
    approvals_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.mkdir(parents=True, exist_ok=True)
    signing_dir.mkdir(parents=True, exist_ok=True)

    attestation_seed = "41" * 32
    seal_seed = "52" * 32

    attestation_pubkey_path = keys_dir / "attestation_pubkey.hex"
    seal_pubkey_path = keys_dir / "seal_pubkey.hex"
    hotl_path = approvals_dir / "hotl_approval.json"
    attestation_signing_key_path = signing_dir / "attestation_signing_key.hex"
    seal_private_key_path = signing_dir / "seal_private_key.hex"

    attestation_pubkey_path.write_text(
        _ed25519_pubkey_hex(attestation_seed) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    seal_pubkey_path.write_text(
        _ed25519_pubkey_hex(seal_seed) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    attestation_signing_key_path.write_text(
        attestation_seed + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    seal_private_key_path.write_text(
        seal_seed + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    hotl_doc = {
        "schema_version": "1.0.0",
        "approval_id": "hotl-tier2-approval",
        "run_id": run_id,
        "approver": "human:test@example.com",
        "approval_type": "pre-proposal",
        "reviewed_artifacts": [
            {
                "id": "intent-spec",
                "hash": "0" * 64,
                "storage_ref": f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            }
        ],
        "decision": "approved",
        "approved_at": "1970-01-01T00:00:00Z",
        "justification": "Tier-2 shared-path approval for deterministic operator-run test.",
        "audit_trail_ref": {
            "id": "audit-hotl-001",
            "storage_ref": f".belgi/runs/{run_id}/inputs/anchors/approvals/hotl_audit.log",
        },
    }
    hotl_path.write_text(
        json.dumps(hotl_doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    return {
        "attestation_pubkey_ref": f"env.attestation_pubkey=.belgi/runs/{run_id}/inputs/anchors/keys/attestation_pubkey.hex",
        "seal_pubkey_ref": f"env.seal_pubkey=.belgi/runs/{run_id}/inputs/anchors/keys/seal_pubkey.hex",
        "hotl_approval_ref": f".belgi/runs/{run_id}/inputs/anchors/approvals/hotl_approval.json",
        "attestation_signing_key_ref": f".belgi/runs/{run_id}/inputs/anchors/signing/attestation_signing_key.hex",
        "seal_private_key_ref": f".belgi/runs/{run_id}/inputs/anchors/signing/seal_private_key.hex",
        "seal_signature_ref": f".belgi/runs/{run_id}/inputs/anchors/signing/seal_signature.b64",
    }


def _refresh_summary_artifact_hashes(repo: Path, attempt_dir: Path, artifact_paths: list[Path]) -> None:
    summary_path = attempt_dir / "run.summary.json"
    summary_obj = json.loads(summary_path.read_text(encoding="utf-8", errors="strict"))
    artifacts = summary_obj.get("artifacts")
    assert isinstance(artifacts, list)
    by_path: dict[str, dict[str, object]] = {}
    for entry in artifacts:
        if isinstance(entry, dict):
            rel = entry.get("path")
            if isinstance(rel, str):
                by_path[rel] = entry

    repo_root = repo.resolve()
    for artifact_path in artifact_paths:
        rel = artifact_path.resolve().relative_to(repo_root).as_posix()
        entry = by_path.get(rel)
        assert isinstance(entry, dict), f"missing artifact entry for {rel}"
        entry["sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()

    summary_path.write_text(
        json.dumps(summary_obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
    )


def _assert_no_persisted_signing_material(out_dir: Path) -> None:
    persisted_secret_paths = sorted(
        p.relative_to(out_dir).as_posix()
        for p in out_dir.rglob("*")
        if p.is_file()
        and ("attestation_signing_key" in p.name or "seal_private_key" in p.name)
    )
    assert persisted_secret_paths == []

    for rel_name in ("EvidenceManifest.json", "SealManifest.json"):
        text = (out_dir / rel_name).read_text(encoding="utf-8", errors="strict")
        assert "attestation_signing_key" not in text
        assert "seal_private_key" not in text


def _run_tier1_and_get_attempt(repo: Path, capsys: object) -> tuple[dict[str, object], Path]:
    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-1", "--base-revision", head_sha])
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id
    assert attempt_dir.is_dir()
    return machine, attempt_dir


def _prepare_shared_run_intent(repo: Path, *, capsys: object, run_id: str, tier_id: str) -> Path:
    rc_new = run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id])
    assert rc_new == 0
    _ = capsys.readouterr()
    return _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
        tier_id=tier_id,
    )


def _write_run_evidence_inputs(repo: Path, *, run_id: str) -> dict[str, str]:
    evidence_dir = repo / ".belgi" / "runs" / run_id / "inputs" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    genesis_seal_path = evidence_dir / "genesis_seal.json"

    authority = load_pinned_trust_anchor(repo)
    payload = authority.expected_genesis_seal_payload()
    genesis_seal_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    return {
        "genesis_seal_ref": f".belgi/runs/{run_id}/inputs/evidence/genesis_seal.json",
    }
