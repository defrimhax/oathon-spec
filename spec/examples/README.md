# spec/examples — Initial illustrative JSON objects (Phase 0)

These examples illustrate object SHAPE only. They are NOT normative test vectors.

PLACEHOLDER CONVENTION (honesty rule: no fabricated
hashes or signatures"): every cryptographic value below is an explicitly marked
placeholder of the form `PLACEHOLDER_*`. Placeholders are NOT valid protocol
values: real digests must decode to exactly 32 bytes (CRYPTOGRAPHY.md §3) and
real signatures must verify. Committed known-answer vectors with real bytes are
a Phase 1 deliverable (CRYPTOGRAPHY.md §15).

Field sets follow MANDATE-001, EVENT-001, CRYPTOGRAPHY.md §8–§13 as amended by
the approved freeze resolutions (ADR-011..015): permitted actions declare
evaluable_fields, events carry evaluation_metadata, segment closes are
writer-key-signed and chained per writer, and key-genesis / writer-authorization
records exist. See docs/unresolved-questions.md for the resolution log.
