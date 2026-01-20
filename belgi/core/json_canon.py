from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(obj: Any) -> bytes:
    """Return canonical JSON bytes (UTF-8, sorted keys, compact separators, trailing LF)."""

    text = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    return text.encode("utf-8", errors="strict")
