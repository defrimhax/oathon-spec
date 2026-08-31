# Oathon — Provenance Classes and Assertion Model

External verifiers need this to interpret evidence bundles: every material
assertion in an Oathon report carries one of four provenance classes plus
machine-readable metadata. This document is extracted verbatim (renumbered)
from the reporting specification; report layout and generation are specified
in the private repository.

## 1. Principle

The report is a view over evidence. The PDF is NOT the root of trust. The
associated evidence bundle is the independently verifiable substrate.

## 2. Provenance classes

Every material assertion MUST be one of:

- **OBSERVED** — Supported directly by successfully verified evidence events.
- **DECLARED** — Supported by a signed customer declaration such as a Mandate.
- **DERIVED** — Deterministically computed from OBSERVED and/or DECLARED inputs.
- **UNVERIFIED** — Insufficient verified evidence exists to support a stronger classification.

A weaker provenance class MUST NOT silently be represented as a stronger
class (INV-013).

## 3. Assertion model

- **REPORT-001** — Every material assertion MUST have machine-readable metadata:

```json
{
  "assertion_id": "...",
  "classification": "OBSERVED",
  "source_refs": [],
  "verification_status": "...",
  "derivation": null
}
```

- **REPORT-002** — Derived claims MUST identify their derivation method and source references.
- **REPORT-003** — The rendered PDF MAY simplify citations visually but MUST preserve traceability to bundle artifacts.
- **REPORT-004** — The report MUST visually distinguish DECLARED from OBSERVED information.
- **REPORT-005** — UNVERIFIED information MUST never be visually presented as verified.

## 4. Interpreting a bundle

A bundle's `assertions.json` holds the full assertion list. `source_refs`
resolve to artifacts inside the bundle (`events/<event_id>`,
`mandates/<mandate_id>`, `segments/<segment_id>`, …) or carry an explicit
`derived:` marker for aggregate claims; `oathon verify-bundle` checks that
every reference resolves (INV-020). Evidence gaps, unanchored segments, and
key-continuity breaks are disclosed in the assertions — never silently
omitted (INV-014).
