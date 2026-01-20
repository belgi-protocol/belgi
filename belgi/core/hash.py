from __future__ import annotations

import hashlib


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_hex_sha256(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    for c in s:
        if c not in "0123456789abcdefABCDEF":
            return False
    return True
