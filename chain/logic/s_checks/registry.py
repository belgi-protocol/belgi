from __future__ import annotations

from chain.logic.s_checks import s1_schema_contract, s2_objectref_binding, s3_sealhash, s4_signature


def get_checks():
    # Stable, canonical order.
    return [
        s1_schema_contract,
        s2_objectref_binding,
        s3_sealhash,
        s4_signature,
    ]
