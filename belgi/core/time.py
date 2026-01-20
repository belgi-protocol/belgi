from __future__ import annotations

from datetime import datetime, timezone


FIXED_TIMESTAMP_UTC_Z = "1970-01-01T00:00:00Z"


def utc_timestamp_iso_z(*, deterministic: bool) -> str:
    if deterministic:
        return FIXED_TIMESTAMP_UTC_Z
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
