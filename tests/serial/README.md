Serial is an exception protocol, not a dumping ground.

Current admitted serial test module budget: 0.

Every future serial test module must live under `tests/serial/`, carry an explicit `pytest.mark.serial` marker, and justify why process-global or platform-global coupling could not be contained in a parallel-safe lane.
