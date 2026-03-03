from __future__ import annotations

import pytest

from chain.logic.base import verify_protocol_identity


pytestmark = pytest.mark.repo_local


def test_protocol_identity_tuple_ignores_source_field() -> None:
    locked_spec = {
        "protocol_pack": {
            "pack_id": "a" * 64,
            "manifest_sha256": "b" * 64,
            "pack_name": "belgi-protocol-pack-v1",
            "source": "builtin",
        }
    }

    result = verify_protocol_identity(
        locked_spec=locked_spec,
        active_pack_id="a" * 64,
        active_manifest_sha256="b" * 64,
        active_pack_name="belgi-protocol-pack-v1",
        gate_id="Q",
    )
    assert result is None

    locked_spec["protocol_pack"]["source"] = "dev-override"
    result_source_change = verify_protocol_identity(
        locked_spec=locked_spec,
        active_pack_id="a" * 64,
        active_manifest_sha256="b" * 64,
        active_pack_name="belgi-protocol-pack-v1",
        gate_id="Q",
    )
    assert result_source_change is None


def test_protocol_identity_tuple_mismatch_fails_closed() -> None:
    locked_spec = {
        "protocol_pack": {
            "pack_id": "a" * 64,
            "manifest_sha256": "b" * 64,
            "pack_name": "pack-a",
            "source": "builtin",
        }
    }

    result = verify_protocol_identity(
        locked_spec=locked_spec,
        active_pack_id="a" * 64,
        active_manifest_sha256="b" * 64,
        active_pack_name="pack-b",
        gate_id="R",
    )
    assert result is not None
    assert result.status == "FAIL"
    assert result.category == "FR-PROTOCOL-IDENTITY-MISMATCH"
    assert "pack_name" in result.message
