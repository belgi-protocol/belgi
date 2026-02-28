from __future__ import annotations

import json
import re
from typing import Any


ALLOWED_KEYS: tuple[str, ...] = ("BELGI_REF", "BELGI_REPO_URL")
_SECRET_LIKE_KEY_RE = re.compile(r"(SECRET|TOKEN|PASSWORD|KEY)", re.IGNORECASE)
SECRET_REMEDIATION = "Do not store secrets in repository variables; use GitHub Secrets."


class SecretLikeVariableError(ValueError):
    """Raised when repository variables include secret-like keys with values."""


def _is_non_empty_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return bool(str(value).strip())


def sanitize_vars_map(raw_json: str) -> dict[str, str]:
    """Parse and sanitize GitHub `vars` map deterministically.

    Rules:
    - Invalid JSON or non-object input returns empty map.
    - Only ALLOWED_KEYS are preserved.
    - Any secret-like key with a non-empty value raises SecretLikeVariableError.
    """

    payload = (raw_json or "").strip()
    if not payload:
        return {}

    try:
        parsed = json.loads(payload)
    except Exception:
        return {}

    if not isinstance(parsed, dict):
        return {}

    # Fail closed if repository vars include secret-like keys.
    for key in sorted(parsed.keys()):
        if not isinstance(key, str):
            continue
        if _SECRET_LIKE_KEY_RE.search(key) and _is_non_empty_value(parsed.get(key)):
            raise SecretLikeVariableError(
                f"Repository variable '{key}' is secret-like. {SECRET_REMEDIATION}"
            )

    sanitized: dict[str, str] = {}
    for key in ALLOWED_KEYS:
        raw = parsed.get(key)
        if raw is None:
            continue
        value = str(raw).strip()
        if value:
            sanitized[key] = value
    return sanitized
