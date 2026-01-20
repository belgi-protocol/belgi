"""BELGI protocol package (core assets + reference implementation).

This package intentionally contains no project-specific semantics.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def __getattr__(name: str):
    if name == "__version__":
        try:
            return version("belgi")
        except PackageNotFoundError:
            return "0.0.0"
    raise AttributeError(name)
