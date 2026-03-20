#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
repo_root_str = str(REPO_ROOT)
if repo_root_str not in sys.path:
    sys.path.insert(0, repo_root_str)

from tools.github_vars_sanitize import SecretLikeVariableError, sanitize_vars_map

DEFAULT_BELGI_REPO_URL = "https://github.com/belgi-protocol/belgi.git"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_LABEL_RE = re.compile(r"[^A-Za-z0-9._-]+")


class WorkflowInputResolutionError(RuntimeError):
    """Raised when workflow inputs cannot be resolved deterministically."""


def _ref_short_label(ref: str) -> str:
    candidate = str(ref or "").strip()
    lowered = candidate.lower()
    if SHA40_RE.fullmatch(lowered):
        return lowered[:12]
    normalized = SAFE_LABEL_RE.sub("-", candidate).strip("-")
    if normalized:
        return normalized[:24]
    return "unresolved-ref"


def resolve_workflow_inputs(
    *,
    belgi_ref_input: str,
    belgi_repo_url_input: str,
    vars_json: str,
) -> dict[str, str]:
    try:
        vars_map = sanitize_vars_map(vars_json)
    except SecretLikeVariableError as e:
        raise WorkflowInputResolutionError(str(e)) from e

    belgi_ref = str(belgi_ref_input or "").strip()
    if not belgi_ref:
        belgi_ref = str(vars_map.get("BELGI_REF", "") or "").strip()
    if not belgi_ref:
        raise WorkflowInputResolutionError(
            "BELGI_REF is required. Set workflow input 'belgi_ref' or repository variable 'BELGI_REF'."
        )

    belgi_repo_url = str(belgi_repo_url_input or "").strip()
    if not belgi_repo_url:
        belgi_repo_url = str(vars_map.get("BELGI_REPO_URL", "") or "").strip()
    if not belgi_repo_url:
        belgi_repo_url = DEFAULT_BELGI_REPO_URL

    return {
        "BELGI_REF": belgi_ref,
        "BELGI_REPO_URL": belgi_repo_url,
        "BELGI_REF_SHORT": _ref_short_label(belgi_ref),
    }


def _append_key_values(path: pathlib.Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8", errors="strict") as handle:
        for key in ("BELGI_REF", "BELGI_REPO_URL", "BELGI_REF_SHORT"):
            handle.write(f"{key}={values[key]}\n")


def _append_outputs(path: pathlib.Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8", errors="strict") as handle:
        handle.write(f"belgi_ref={values['BELGI_REF']}\n")
        handle.write(f"belgi_repo_url={values['BELGI_REPO_URL']}\n")
        handle.write(f"belgi_ref_short={values['BELGI_REF_SHORT']}\n")


def main(argv: list[str] | None = None) -> int:
    del argv

    env_path_raw = os.environ.get("GITHUB_ENV", "").strip()
    if not env_path_raw:
        print("GITHUB_ENV is not set", file=sys.stderr)
        return 1

    try:
        resolved = resolve_workflow_inputs(
            belgi_ref_input=os.environ.get("BELGI_REF_INPUT", ""),
            belgi_repo_url_input=os.environ.get("BELGI_REPO_URL_INPUT", ""),
            vars_json=os.environ.get("BELGI_VARS_JSON", ""),
        )
    except WorkflowInputResolutionError as e:
        print(str(e), file=sys.stderr)
        return 1

    env_path = pathlib.Path(env_path_raw)
    _append_key_values(env_path, resolved)

    output_path_raw = os.environ.get("GITHUB_OUTPUT", "").strip()
    if output_path_raw:
        _append_outputs(pathlib.Path(output_path_raw), resolved)

    print(
        "Resolved BELGI workflow inputs "
        f"(ref={resolved['BELGI_REF']}, repo={resolved['BELGI_REPO_URL']}, short={resolved['BELGI_REF_SHORT']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
