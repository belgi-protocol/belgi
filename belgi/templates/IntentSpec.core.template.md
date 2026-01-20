# IntentSpec (Core) — Template (Core Intent Contract v1)

This file is human-authored, but **only** the single fenced YAML block below is machine-parsed.

Deterministic compilation/mapping rule (v1):
- `IntentSpec.intent_id` → `LockedSpec.intent.intent_id`
- `IntentSpec.title` → `LockedSpec.intent.title`
- `IntentSpec.goal` → `LockedSpec.intent.narrative`
- `IntentSpec.acceptance.success_criteria[]` → `LockedSpec.intent.success_criteria` as a newline-joined list with `- ` prefix per item, preserving order.
- `LockedSpec.intent.scope` MUST be a deterministic summary string derived from `IntentSpec.scope.*`:
  - `allowed_dirs: [<allowed_dirs joined by ', '>]; forbidden_dirs: [<forbidden_dirs joined by ', '>]; max_touched_files: <value or null>; max_loc_delta: <value or null>`

Related deterministic mappings (v1):
- `IntentSpec.scope.allowed_dirs[]` → `LockedSpec.constraints.allowed_paths[]` (exact array equality; preserve order)
- `IntentSpec.scope.forbidden_dirs[]` → `LockedSpec.constraints.forbidden_paths[]` (exact array equality; preserve order)
- `IntentSpec.scope.max_touched_files` → `LockedSpec.constraints.max_touched_files` (if present)
- `IntentSpec.scope.max_loc_delta` → `LockedSpec.constraints.max_loc_delta` (if present)
- `IntentSpec.tier.tier_pack_id` → `LockedSpec.tier.tier_id`
- `IntentSpec.doc_impact` → `LockedSpec.doc_impact` (if present/required by tier)
- `IntentSpec.publication_intent` → `LockedSpec.publication_intent` (required by tier for tier-2/3)

Rules:
- Do not add a second YAML block.
- Do not put machine-meaningful data outside the YAML block.
- Use repo-relative paths with `/` separators.
- Do not use wildcards (`*`, `?`) or `..` segments in any paths.

```yaml
intent_id: "INTENT-0001"
title: "Concise change title"
# goal: 1–3 sentences (human guideline; core gates do not count sentences).
goal: "What should change and why. Keep this short and testable."

scope:
  # Directories/prefixes the change is allowed to touch.
  allowed_dirs:
    - "src/"

  # Directories/prefixes the change must not touch.
  forbidden_dirs:
    - "secrets/"

  # Optional scope budgets (integers >= 0)
  # max_touched_files: 10
  # max_loc_delta: 500

acceptance:
  # Optional commands/patterns for required tests (core gates do not interpret these unless mapped by policy).
  # required_tests:
  #   - "pytest -q"

  # Success criteria (at least 1). Keep each item short and mechanically checkable.
  success_criteria:
    - "All required tests pass."

# Tier pack selection (must match a supported tier ID, e.g. tier-0..tier-3).
tier:
  tier_pack_id: "tier-2"

# Documentation impact declaration.
# - required_paths may be [] to explicitly state "no doc updates required".
# - If required_paths is [], note_on_empty MUST be non-empty.
doc_impact:
  required_paths:
    - "README.md"
  note_on_empty: "Docs updated to reflect behavior change."

# Publication intent (required for tier-2/3).
# - publish: true means the run intends to produce public-safe publishable artifacts.
# - profile selects the C3 docs compiler profile; selection enforcement is fail-closed per gate/policy.
publication_intent:
  publish: true
  profile: "public"

# Optional: waiver requests (core gates ignore unless mapped by policy).
# Can be an empty list.
# waivers_requested: []

# Optional: project-specific extension object.
# Core gates do not interpret this unless explicitly mapped.
# project_extension: {}
```