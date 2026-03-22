#!/usr/bin/env python3
"""Thin shipped BELGI CLI shim over the cli_app entrypoint."""

from __future__ import annotations

import sys
from types import ModuleType

import belgi.cli_app.commands.bundle as _bundle
import belgi.cli_app.commands.pack as _pack
import belgi.cli_app.commands.policy as _policy
import belgi.cli_app.commands.run as _run
import belgi.cli_app.commands.stage as _stage
import belgi.cli_app.commands.verify as _verify
import belgi.cli_app.commands.waiver as _waiver
from belgi.cli_app import render as _render
from belgi.cli_app.main import main

_OWNER_MODULES = (_render, _stage, _policy, _pack, _bundle, _waiver, _verify, _run)


def _owner_for_name(name: str):
    for module in _OWNER_MODULES:
        if hasattr(module, name):
            return module
    return None


class _CliShimModule(ModuleType):
    def __getattr__(self, name: str):
        if name == "main":
            return main
        owner = _owner_for_name(name)
        if owner is not None:
            return getattr(owner, name)
        raise AttributeError(name)

    def __dir__(self) -> list[str]:
        visible = {"main"}
        for module in _OWNER_MODULES:
            visible.update(dir(module))
        return sorted(set(super().__dir__()) | visible)

    def __setattr__(self, name: str, value) -> None:
        if name != "__class__":
            owner = _owner_for_name(name)
            if owner is not None:
                setattr(owner, name, value)
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _CliShimModule

__all__ = ["main"]


if __name__ == "__main__":
    sys.exit(main())
