from __future__ import annotations

import argparse
from dataclasses import dataclass


@dataclass(frozen=True)
class RunRegistry:
    root: argparse.ArgumentParser
    new: argparse.ArgumentParser


@dataclass(frozen=True)
class WaiverRegistry:
    root: argparse.ArgumentParser
    new: argparse.ArgumentParser
    apply: argparse.ArgumentParser


@dataclass(frozen=True)
class BundleRegistry:
    root: argparse.ArgumentParser
    check: argparse.ArgumentParser


@dataclass(frozen=True)
class PackRegistry:
    root: argparse.ArgumentParser
    build: argparse.ArgumentParser
    verify: argparse.ArgumentParser


@dataclass(frozen=True)
class PolicyRegistry:
    root: argparse.ArgumentParser
    stub: argparse.ArgumentParser
    check_overlay: argparse.ArgumentParser


@dataclass(frozen=True)
class StageSRegistry:
    root: argparse.ArgumentParser
    seal: argparse.ArgumentParser
    verify: argparse.ArgumentParser


@dataclass(frozen=True)
class StageRegistry:
    root: argparse.ArgumentParser
    c1: argparse.ArgumentParser
    q: argparse.ArgumentParser
    r: argparse.ArgumentParser
    c3: argparse.ArgumentParser
    s: StageSRegistry


@dataclass(frozen=True)
class ManifestRegistry:
    root: argparse.ArgumentParser
    add: argparse.ArgumentParser


@dataclass(frozen=True)
class CliRegistry:
    parser: argparse.ArgumentParser
    about: argparse.ArgumentParser
    init: argparse.ArgumentParser
    manifest: ManifestRegistry
    supplychain_scan: argparse.ArgumentParser
    adversarial_scan: argparse.ArgumentParser
    run: RunRegistry
    verify: argparse.ArgumentParser
    waiver: WaiverRegistry
    bundle: BundleRegistry
    pack: PackRegistry
    policy: PolicyRegistry
    stage: StageRegistry
