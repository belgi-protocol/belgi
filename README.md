# BELGI (Archived Pre-Reset Line)

This repository is BELGI's archived pre-reset implementation line.

It is kept for provenance, migration reference, and historical comparison. It
is not the active normative implementation line.

## Repository Position

- archived pre-reset implementation history
- retained for provenance, migration reference, and comparison
- not authoritative for current BELGI semantics, conformance, or product
  guidance
- not the recommended starting point for new adoption

See [CHANGELOG.md](CHANGELOG.md) for the factual history of this line.

## Why This Repository Was Archived

Much of this repository accumulated before the BELGI specification family,
semantic contracts, and owner boundaries were fully locked. The result was not
just normal technical debt. The seams were blurred, large monolithic modules
accumulated, and ownership drifted across surfaces that now need hard
separation.

In practical terms, this line mixed concerns that now need separate owners:

- substrate and infrastructure
- core semantic-kernel logic
- profile governance and vocabulary
- preserved-carrier and replay-package construction
- replay lifting, procedure, and reporting
- product CLI, orchestration, and research/runtime surfaces

It also produced structural problems that were not honest to treat as a
cosmetic refactor:

- semantic and runtime concerns sharing the same modules
- owner boundaries scattered across broad operational monoliths
- profile and governance meaning leaking into product and workflow code
- preserved-carrier and replay concerns shaped by producer-side history
- local convenience seams competing with the actual semantic owners

Once the repository reached that shape, incremental cleanup stopped being the
truthful path. It would have kept old seams alive under new names.

Continuing to patch this repository in place would preserve the wrong
inheritance:

- historical module ownership from before the BELGI contracts were locked
- compatibility shims and aliases whose main purpose would be to protect old
  layout rather than current meaning
- accidental runtime contracts stronger than the specification
- product and workflow assumptions leaking into semantic owners
- producer-side history shaping preserved-carrier and replay logic

For BELGI, that is the higher-risk path. A clean spec-first rebuild from the
stabilized contracts is the more honest engineering decision and the more
verifiable, lower-risk, and conformant implementation path.

## Successor Direction

Active BELGI implementation work is being rebuilt around the locked owner
families:

1. `substrate/` - infrastructure only
2. `core/` - semantic kernel
3. `profile/` - governance and vocabulary
4. `carrier/` - preserved-carrier and replay-package construction
5. `replay/` - lifting, replay procedure, and replay report
6. `product/` - CLI, orchestration, and research runner

This split is the point of the reset. It gives each layer a narrow
responsibility, restores semantic authority to the correct owners, and makes
conformance claims easier to audit.

## Migration Posture

This archive does not define an in-place upgrade path.

As of April 16, 2026, this repository has zero users at archive time.
Accordingly:

- no deprecation window is being maintained
- no backward-compatibility shims are being added for this archived line
- no attempt is being made to preserve old module paths as the new normative
  shape
- migration use is conceptual and forensic, not drop-in

If you need BELGI going forward, start from the successor implementation line
and the stabilized BELGI specification family. Use this archive only to inspect
prior decisions, compare ownership shapes, or recover historical implementation
detail.

## What This Repository Is Still For

- provenance of earlier BELGI implementation work
- historical comparison against the successor layered architecture
- migration reference when tracing old names, flows, or artifacts
- preservation of pre-reset design and implementation history

## What This Repository Is Not For

- new production adoption
- current conformance claims
- normative BELGI architecture
- authoritative CLI or runtime guidance
- treating old runtime behavior as the specification

## Archive Rationale In One Sentence

This repository is archived because a clean rebuild from stabilized BELGI
contracts is more honest, lower-risk, more verifiable, and more conformant
than continuing to retrofit formal BELGI semantics onto a codebase whose
blurred seams, monolithic modules, and scattered owners were shaped before
those semantics were locked.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## Trademark Notice

BELGI is a trademark of the BELGI Protocol Founding Maintainer. The code is
available under the Apache 2.0 License, but that license does not grant
permission to use the BELGI name, trademarks, service marks, or product names
except as required for reasonable and customary use in describing the origin of
the work.
