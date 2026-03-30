# Exit Codes (Normative Contract)

Status: canonical operations contract for BELGI exit-code surfaces.

## Scope

This document defines the authoritative public CLI exit-code model and the
separation from internal runner/tool surfaces.

## Public CLI Surface (`belgi`)

The installable `belgi` CLI contract is:

| Code | Class | Meaning |
|---|---|---|
| `0` | `GO` | Command completed successfully. |
| `10` | `NO-GO` | Deterministic policy/evidence/contract failure. |
| `20` | `USER_ERROR` | Usage/argument/input-contract failure, including normalized legacy `rc=3` returns. |
| `30` | `INTERNAL_ERROR` | Unexpected internal exception path or explicit `RC_INTERNAL_ERROR` return. |

### Default public CLI boundary normalization

This is the normalization surface used by the main public CLI membrane.

| Raw rc | Public CLI rc | Notes |
|---|---|---|
| `1` | `10` | legacy NO-GO path |
| `2` | `10` | legacy NO-GO path |
| `3` | `20` | legacy USER_ERROR path |
| `30` | `30` | explicit `RC_INTERNAL_ERROR` stays `30` |
| `99` | `30` | representative other non-zero fallback path |

Any other non-zero fallback path on the default public CLI boundary also normalizes to `30`.

### `stage` forwarder public CLI boundary normalization

This is the normalization surface used by public `belgi stage ...` forwarders.

| Raw rc | Public CLI rc | Notes |
|---|---|---|
| `2` | `10` | chain NO-GO path |
| `3` | `20` | chain user/input failure path |
| `1` | `30` | non-contract stage fallback is internal at the public CLI boundary |
| `30` | `30` | explicit `RC_INTERNAL_ERROR` stays `30` |
| `99` | `30` | representative other non-zero fallback path |

Any other non-zero fallback path on the `stage` forwarder boundary also normalizes to `30`.

Public CLI commands must return only `{0,10,20,30}`.

## Internal Runner Surfaces (Non-Public RC Model)

These remain valid internal contracts and are not the public CLI RC model:

- `chain/gate_q_verify.py`: `0/2/3`
- `chain/gate_r_verify.py`: `0/2/3`
- `chain/gate_s_verify.py`: `0/2/3`
- `tools/sweep.py`: `0/1/2` (declared consistency outcomes)
- `tools/rehash.py`: `0/2`

When the public CLI wraps an internal surface, the public CLI still emits the
public model above.
