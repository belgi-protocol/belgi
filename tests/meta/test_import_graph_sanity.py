import pytest

pytestmark = pytest.mark.repo_local


def test_import_graph_sanity() -> None:
    # These should import without any circular dependency errors.
    import belgi.core.jail  # noqa: F401
    import belgi.protocol.pack  # noqa: F401
    import chain.logic.base  # noqa: F401
