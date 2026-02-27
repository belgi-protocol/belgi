# Exit Codes (SSOT)

This file is the tracked source of truth for BELGI exit-code surfaces.

## Public CLI surface (`belgi`)

The installable `belgi` CLI uses this normalized model:

- `0`: `GO`
- `10`: `NO-GO` (policy/evidence/contract failure)
- `20`: `USER_ERROR` (usage/argument/input contract, including normalized legacy `rc=3` returns)
- `30`: `INTERNAL_ERROR` (unexpected exception paths or explicit `RC_INTERNAL_ERROR` returns)

Rule: public CLI commands must return only `{0,10,20,30}`.

## Internal runner surfaces (non-public RC model)

These internal tools keep their own deterministic RC contracts and are not the
public `belgi` CLI RC model:

- `chain/gate_q_verify.py`: `0/2/3`
- `chain/gate_r_verify.py`: `0/2/3`
- `chain/gate_s_verify.py`: `0/2/3`
- `tools/sweep.py`: `0/1/2` for declared consistency outcomes
- `tools/rehash.py`: `0/2`

If a public CLI command wraps an internal runner, CLI output RCs still follow
the public model above.
