#!/usr/bin/env python3
"""Generate a deterministic operator report (Markdown) from BELGI run artifacts.

Purpose:
- Produce a human-readable `AuditReport.md` summarizing a run.
- Produce `AuditReport.sha256.txt` (sha256sum-style manifest) so any manual edits
  to report bytes are detectable.

Determinism posture:
- No timestamps are generated.
- Output is written with LF newlines.
- Ordering is preserved from input artifacts (invariants order; verify_report order).

Security posture:
- Repo-root confinement for all authoritative IO (reject absolute paths, '..', NUL).
- Symlink defense: reject any symlink targets or symlink parents for security-scoped IO.

Run:
  python -m tools.report \
    --repo . \
    --locked-spec LockedSpec.json \
    --evidence-manifest EvidenceManifest.json \
    --verify-report policy/verify_report.json \
    --gate-q-verdict GateVerdict.Q.json \
    --gate-r-verdict GateVerdict.R.json \
    --seal-manifest SealManifest.json

Integrity check:
  python -m tools.rehash sha256-txt --repo . --manifest AuditReport.sha256.txt --check
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


_REPO_ROOT_FOR_IMPORTS = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT_FOR_IMPORTS) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT_FOR_IMPORTS))

from belgi.core.jail import resolve_repo_rel_path
from belgi.core.hash import sha256_bytes
from belgi.core.jail import safe_relpath
from belgi.core.jail import resolve_storage_ref
from chain.logic.base import load_json


class _UserInputError(RuntimeError):
    pass


def _require_str(obj: dict[str, Any], key: str, *, where: str) -> str:
    v = obj.get(key)
    if not isinstance(v, str) or not v:
        raise _UserInputError(f"{where}: missing/invalid '{key}'")
    return v


def _yaml_quote(s: str) -> str:
    # Deterministic minimal YAML quoting: double-quote + escape backslash and double-quote.
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _read_json_dict(path: Path, *, where: str) -> dict[str, Any]:
    try:
        obj = load_json(path)
    except Exception as e:
        raise _UserInputError(f"{where}: failed to read JSON: {path.as_posix()}: {e}") from e
    if not isinstance(obj, dict):
        raise _UserInputError(f"{where}: expected JSON object")
    return obj


def _extract_genesis_from_evidence(
    repo_root: Path,
    locked_spec: dict[str, Any],
    evidence_manifest: dict[str, Any],
) -> tuple[dict[str, str], str]:
    tier_id = str(locked_spec.get("tier", {}).get("tier_id") or "")
    if tier_id != "tier-3":
        return {}, ""

    artifacts = evidence_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise _UserInputError("Tier-3: EvidenceManifest.artifacts must be a list")

    genesis = [a for a in artifacts if isinstance(a, dict) and a.get("kind") == "genesis_seal"]
    if len(genesis) != 1:
        raise _UserInputError(f"Tier-3: expected exactly one genesis_seal artifact, got {len(genesis)}")

    g = genesis[0]
    storage_ref = g.get("storage_ref")
    declared_hash = g.get("hash")
    if not isinstance(storage_ref, str) or not storage_ref:
        raise _UserInputError("Tier-3: genesis_seal.storage_ref missing/invalid")
    if not isinstance(declared_hash, str) or not declared_hash:
        raise _UserInputError("Tier-3: genesis_seal.hash missing/invalid")

    payload_path = resolve_storage_ref(repo_root, storage_ref)
    payload_bytes = payload_path.read_bytes()
    actual = sha256_bytes(payload_bytes)
    if actual != declared_hash:
        raise _UserInputError("Tier-3: genesis_seal sha256(bytes) mismatch (declared != actual)")

    try:
        payload_obj = json.loads(payload_bytes.decode("utf-8", errors="strict"))
    except Exception as e:
        raise _UserInputError(f"Tier-3: genesis_seal payload invalid JSON: {e}") from e

    if not isinstance(payload_obj, dict):
        raise _UserInputError("Tier-3: genesis_seal payload must be a JSON object")

    philosophy = _require_str(payload_obj, "philosophy", where="Tier-3 genesis_seal")
    dedication = _require_str(payload_obj, "dedication", where="Tier-3 genesis_seal")
    architect = _require_str(payload_obj, "architect", where="Tier-3 genesis_seal")

    # Defense-in-depth: ensure the reported strings match the canonical genesis payload checked into the repo.
    canonical_path = resolve_repo_rel_path(
        repo_root,
        "belgi/genesis/GenesisSealPayload.json",
        must_exist=True,
        must_be_file=True,
        allow_backslashes=False,
        forbid_symlinks=True,
    )
    canonical = _read_json_dict(canonical_path, where="canonical GenesisSealPayload")
    if philosophy != _require_str(canonical, "philosophy", where="canonical GenesisSealPayload"):
        raise _UserInputError("Tier-3: genesis_seal philosophy mismatch vs canonical GenesisSealPayload.json")
    if dedication != _require_str(canonical, "dedication", where="canonical GenesisSealPayload"):
        raise _UserInputError("Tier-3: genesis_seal dedication mismatch vs canonical GenesisSealPayload.json")
    if architect != _require_str(canonical, "architect", where="canonical GenesisSealPayload"):
        raise _UserInputError("Tier-3: genesis_seal architect mismatch vs canonical GenesisSealPayload.json")

    return {"philosophy": philosophy, "dedication": dedication, "architect": architect}, declared_hash


def _format_gate_verdict(verdict: dict[str, Any], *, title: str) -> str:
    lines: list[str] = []
    lines.append(f"## {title}\n")

    gate_id = verdict.get("gate_id")
    v = verdict.get("verdict")
    fc = verdict.get("failure_category")
    evaluated_at = verdict.get("evaluated_at")
    evaluator = verdict.get("evaluator")

    if isinstance(gate_id, str):
        lines.append(f"- gate_id: {gate_id}\n")
    if isinstance(v, str):
        lines.append(f"- verdict: {v}\n")
    if fc is None:
        lines.append("- failure_category: null\n")
    elif isinstance(fc, str):
        lines.append(f"- failure_category: {fc}\n")
    if isinstance(evaluated_at, str):
        lines.append(f"- evaluated_at: {evaluated_at}\n")
    if isinstance(evaluator, str):
        lines.append(f"- evaluator: {evaluator}\n")

    failures = verdict.get("failures")
    if isinstance(failures, list) and failures:
        lines.append("\n### Failures\n")
        for f in failures:
            if not isinstance(f, dict):
                continue
            fid = f.get("id")
            msg = f.get("message")
            rid = f.get("rule_id")
            cat = f.get("category")
            bits: list[str] = []
            if isinstance(fid, str) and fid:
                bits.append(fid)
            if isinstance(cat, str) and cat:
                bits.append(cat)
            if isinstance(rid, str) and rid:
                bits.append(rid)
            head = " / ".join(bits) if bits else "failure"
            if isinstance(msg, str) and msg:
                lines.append(f"- {head}: {msg}\n")
            else:
                lines.append(f"- {head}\n")

    lines.append("\n")
    return "".join(lines)


def _format_verify_report(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("## Gate R Results (verify_report)\n\n")

    results = report.get("results")
    if not isinstance(results, list):
        lines.append("verify_report.results missing or not a list.\n\n")
        return "".join(lines)

    primary: dict[str, Any] | None = None
    for r in results:
        if isinstance(r, dict) and r.get("status") == "FAIL":
            primary = r
            break

    if primary is not None:
        cid = primary.get("check_id")
        msg = primary.get("message")
        lines.append("Primary cause (first FAIL):\n")
        if isinstance(cid, str) and cid:
            lines.append(f"- check_id: {cid}\n")
        if isinstance(msg, str) and msg:
            lines.append(f"- message: {msg}\n")
        ptrs = primary.get("pointers")
        if isinstance(ptrs, list):
            p = [x for x in ptrs if isinstance(x, str) and x]
            if p:
                lines.append(f"- pointers: {'; '.join(p)}\n")
        lines.append("\n")

    lines.append("### Ordered results\n")
    for r in results:
        if not isinstance(r, dict):
            continue
        cid = r.get("check_id")
        status = r.get("status")
        msg = r.get("message")
        if not isinstance(cid, str) or not cid:
            continue
        s = status if isinstance(status, str) and status else "<unknown>"
        m = msg if isinstance(msg, str) and msg else ""
        if m:
            lines.append(f"- {cid}: {s} — {m}\n")
        else:
            lines.append(f"- {cid}: {s}\n")

    lines.append("\n")
    return "".join(lines)


def _format_seal_status(seal_manifest: dict[str, Any] | None) -> str:
    lines: list[str] = []
    lines.append("## Sealed Status\n\n")

    if seal_manifest is None:
        lines.append("UNSEALED: SealManifest not provided.\n\n")
        return "".join(lines)

    lines.append("SEALED (SealManifest provided):\n")
    for k in ("sealed_at", "signer", "final_commit_sha", "seal_hash", "signature_alg"):
        v = seal_manifest.get(k)
        if isinstance(v, str) and v:
            lines.append(f"- {k}: {v}\n")

    lines.append("\n")
    return "".join(lines)


def _atomic_write_text_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp.report")
    with tmp.open("w", encoding="utf-8", errors="strict", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".", help="Repo root")
    ap.add_argument("--locked-spec", required=True, help="LockedSpec.json (repo-relative)")
    ap.add_argument("--evidence-manifest", help="EvidenceManifest.json (required for tier-3)")
    ap.add_argument("--verify-report", help="verify_report.json from chain/gate_r_verify.py")
    ap.add_argument("--gate-q-verdict", help="GateVerdict.json for gate Q")
    ap.add_argument("--gate-r-verdict", help="GateVerdict.json for gate R")
    ap.add_argument("--seal-manifest", help="SealManifest.json (optional)")
    ap.add_argument("--out-md", default="AuditReport.md", help="Output markdown path (repo-relative)")
    ap.add_argument("--out-sha", default="AuditReport.sha256.txt", help="Output sha256 manifest path (repo-relative)")
    args = ap.parse_args(argv)

    repo_root = Path(args.repo).resolve()

    try:
        locked_spec_path = resolve_repo_rel_path(
            repo_root,
            args.locked_spec,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=True,
            forbid_symlinks=True,
        )
        locked_spec = _read_json_dict(locked_spec_path, where="LockedSpec")

        tier_id = str(locked_spec.get("tier", {}).get("tier_id") or "")
        run_id = str(locked_spec.get("run_id") or "")

        evidence_manifest: dict[str, Any] | None = None
        if args.evidence_manifest:
            em_path = resolve_repo_rel_path(
                repo_root,
                args.evidence_manifest,
                must_exist=True,
                must_be_file=True,
                allow_backslashes=True,
                forbid_symlinks=True,
            )
            evidence_manifest = _read_json_dict(em_path, where="EvidenceManifest")

        if tier_id == "tier-3" and evidence_manifest is None:
            raise _UserInputError("Tier-3 requires --evidence-manifest to embed genesis insignia")

        genesis_fields, genesis_hash = ({}, "")
        if evidence_manifest is not None:
            genesis_fields, genesis_hash = _extract_genesis_from_evidence(repo_root, locked_spec, evidence_manifest)

        verify_report: dict[str, Any] | None = None
        if args.verify_report:
            vr_path = resolve_repo_rel_path(
                repo_root,
                args.verify_report,
                must_exist=True,
                must_be_file=True,
                allow_backslashes=True,
                forbid_symlinks=True,
            )
            verify_report = _read_json_dict(vr_path, where="verify_report")

        gate_q_verdict: dict[str, Any] | None = None
        if args.gate_q_verdict:
            q_path = resolve_repo_rel_path(
                repo_root,
                args.gate_q_verdict,
                must_exist=True,
                must_be_file=True,
                allow_backslashes=True,
                forbid_symlinks=True,
            )
            gate_q_verdict = _read_json_dict(q_path, where="GateVerdict(Q)")

        gate_r_verdict: dict[str, Any] | None = None
        if args.gate_r_verdict:
            r_path = resolve_repo_rel_path(
                repo_root,
                args.gate_r_verdict,
                must_exist=True,
                must_be_file=True,
                allow_backslashes=True,
                forbid_symlinks=True,
            )
            gate_r_verdict = _read_json_dict(r_path, where="GateVerdict(R)")

        seal_manifest: dict[str, Any] | None = None
        if args.seal_manifest:
            s_path = resolve_repo_rel_path(
                repo_root,
                args.seal_manifest,
                must_exist=True,
                must_be_file=True,
                allow_backslashes=True,
                forbid_symlinks=True,
            )
            seal_manifest = _read_json_dict(s_path, where="SealManifest")

        out_md = resolve_repo_rel_path(
            repo_root,
            args.out_md,
            must_exist=False,
            must_be_file=True,
            allow_backslashes=True,
            forbid_symlinks=True,
        )
        out_sha = resolve_repo_rel_path(
            repo_root,
            args.out_sha,
            must_exist=False,
            must_be_file=True,
            allow_backslashes=True,
            forbid_symlinks=True,
        )

        parts: list[str] = []

        if tier_id == "tier-3":
            parts.append("---\n")
            parts.append(f"belgi_tier: {_yaml_quote(tier_id)}\n")
            parts.append(f"run_id: {_yaml_quote(run_id)}\n")
            parts.append(f"genesis_architect: {_yaml_quote(genesis_fields['architect'])}\n")
            parts.append(f"genesis_dedication: {_yaml_quote(genesis_fields['dedication'])}\n")
            parts.append(f"genesis_philosophy: {_yaml_quote(genesis_fields['philosophy'])}\n")
            parts.append(f"genesis_seal_sha256: {_yaml_quote(genesis_hash)}\n")
            parts.append("---\n\n")

        parts.append("# BELGI Audit Report\n\n")
        parts.append("## Summary\n\n")
        parts.append(f"- run_id: {run_id}\n")
        parts.append(f"- tier: {tier_id}\n")
        parts.append("\n")

        intent = locked_spec.get("intent")
        if isinstance(intent, dict):
            parts.append("## Intent\n\n")
            for k in ("intent_id", "title", "narrative", "scope", "success_criteria"):
                v = intent.get(k)
                if isinstance(v, str) and v:
                    parts.append(f"- {k}: {v}\n")
            parts.append("\n")

        invariants = locked_spec.get("invariants")
        parts.append("## Invariants\n\n")
        if isinstance(invariants, list) and invariants:
            for inv in invariants:
                if not isinstance(inv, dict):
                    continue
                inv_id = inv.get("id")
                sev = inv.get("severity")
                desc = inv.get("description")
                head = []
                if isinstance(inv_id, str) and inv_id:
                    head.append(inv_id)
                if isinstance(sev, str) and sev:
                    head.append(sev)
                prefix = " / ".join(head) if head else "invariant"
                if isinstance(desc, str) and desc:
                    parts.append(f"- {prefix}: {desc}\n")
                else:
                    parts.append(f"- {prefix}\n")
        else:
            parts.append("(none)\n")
        parts.append("\n")

        if gate_q_verdict is not None:
            parts.append(_format_gate_verdict(gate_q_verdict, title="Gate Q Verdict"))
        else:
            parts.append("## Gate Q Verdict\n\n(not provided)\n\n")

        if verify_report is not None:
            parts.append(_format_verify_report(verify_report))
        elif gate_r_verdict is not None:
            parts.append(_format_gate_verdict(gate_r_verdict, title="Gate R Verdict"))
        else:
            parts.append("## Gate R\n\n(not provided)\n\n")

        parts.append(_format_seal_status(seal_manifest))

        md_text = "".join(parts)
        if not md_text.endswith("\n"):
            md_text += "\n"

        _atomic_write_text_lf(out_md, md_text)

        md_rel = out_md.name
        try:
            md_rel = out_md.resolve().relative_to(out_sha.parent.resolve()).as_posix()
        except Exception:
            md_rel = out_md.name

        digest = sha256_bytes(md_text.encode("utf-8", errors="strict"))
        sha_text = f"{digest}  {md_rel}\n"
        _atomic_write_text_lf(out_sha, sha_text)

        print(f"Wrote: {safe_relpath(repo_root, out_md)}")
        print(f"Wrote: {safe_relpath(repo_root, out_sha)}")
        return 0

    except _UserInputError as e:
        print(f"NO-GO: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Usage error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
