# Oathon Protocol v0.1 — Independent Implementer's Guide

Frozen candidate semantics (tag `v0.1-rc1` + Phase 1 schemas/vectors).
Normative sources, in authority order: INVARIANTS.md, SECURITY.md,
CRYPTOGRAPHY.md, SPEC.md, PROVENANCE.md. This document is a guide; where it
and a normative document disagree, the normative document wins and the
discrepancy is a bug in this file.

## 1. What you need to interoperate

1. **Primitives** — SHA-256, Ed25519, RFC 8785 (JCS) canonical JSON, UTF-8
   without BOM, base64url without padding (CRYPTOGRAPHY.md §1).
2. **JSON restrictions** — reject duplicate keys, NaN, ±Infinity; integers
   stay in the IEEE-754 safe domain; money = `{minor_units: int, currency}`
   (§2). All protocol timestamps use `YYYY-MM-DDTHH:MM:SS.sssZ` (CRYPTO-006).
3. **Schemas** — the JSON Schemas under `spec/*/v0.1/*.schema.json` are
   normative. Signed objects reject unknown fields (`additionalProperties:
   false`); extension requires a new `spec_version`.

## 2. Object types and domain strings

| Object | Schema | Domain string (append one 0x00 byte) |
|---|---|---|
| Mandate | spec/mandate/v0.1/mandate.schema.json | `WARRANT-MANDATE-SIGN-V0.1` |
| Revocation | spec/mandate/v0.1/revocation.schema.json | `WARRANT-REVOCATION-SIGN-V0.1` |
| Key genesis | spec/keys/v0.1/key-genesis.schema.json | `WARRANT-KEY-GENESIS-SIGN-V0.1` |
| Key transition | spec/keys/v0.1/key-transition.schema.json | `WARRANT-KEY-TRANSITION-SIGN-V0.1` |
| Writer authorization | spec/keys/v0.1/writer-authorization.schema.json | `WARRANT-WRITER-AUTH-SIGN-V0.1` |
| Evidence event (hashed, not signed) | spec/evidence/v0.1/event.schema.json | `WARRANT-EVENT-HASH-V0.1` |
| Segment close | spec/evidence/v0.1/segment-close.schema.json | `WARRANT-SEGMENT-SIGN-V0.1` |
| JSON digest helper | — | `WARRANT-DIGEST-JSON-V0.1` |
| Byte digest helper | — | `WARRANT-DIGEST-BYTES-V0.1` |
| Anchor input | — | `WARRANT-ANCHOR-INPUT-V0.1` |

## 3. Byte constructions

- **Signing input** (CRYPTO §6): deep-copy the object, delete only
  `signature.value`, JCS-canonicalize, UTF-8 encode, prepend domain bytes,
  Ed25519-sign.
- **Event hash** (CRYPTO §10): the event object *without* `event_hash`
  (but *with* `prev_hash` — genesis uses `null`) is canonicalized; hash =
  SHA-256(domain ‖ canonical). Coverage is total: every present field except
  `event_hash`. Server metadata never enters the event object.
- **Digest strings** (CRYPTO §3): `sha256:` + base64url(32 bytes, no pad).
- **Key IDs** (CRYPTO §4): `ed25519:` + base64url(SHA-256(raw 32-byte public
  key)). Key-carrying JSON fields hold base64url of the raw 32 bytes.
- **Anchor input** (CRYPTO §14): SHA-256(domain ‖ JCS(complete signed
  segment-close record)); this is the RFC 3161 messageImprint and also the
  value referenced by the next segment's `prev_segment_close_hash`.

## 4. Chains

- **Events** (intra-segment): `sequence` from 0 by +1 (INV-004); each
  non-genesis event's `prev_hash` equals the predecessor's `event_hash`
  (INV-003); one writer per segment (INV-005).
- **Segments** (per writer): `segment_sequence` from 0 by +1;
  `prev_segment_close_hash` = anchor-input digest of the previous close
  (SEGMENT-010, INV-023).
- **Keys**: genesis record is self-signed (KEY-010); rotations are signed by
  the old key (KEY-005); administrative recovery is marked and breaks
  cryptographic continuity (KEY-006). Segment closes are signed by writer
  keys certified by writer-authorization records (KEY-009): verify
  close-signature → writer key → authorization (org/agent/writer_id match +
  window covers signing time) → org key history.

## 5. Known-answer vectors

`spec/vectors/v0.1/` is the conformance suite:

- `keys.json` — INSECURE deterministic test keys
  (seed = SHA-256(`WARRANT-INSECURE-TEST-KEY:<label>`)).
- `vectors.json` — 21 cases covering every construction in CRYPTOGRAPHY.md
  §15 with expected canonical bytes, hashes, signatures (Ed25519 is
  deterministic — byte equality is required), and expected
  verification outcomes.
- `schema-cases.json` — 46 raw-text validation cases (includes duplicate-key
  and NaN cases that only exist at the text layer).

A conforming implementation MUST reproduce every expected value and outcome.

## 6. Reference tooling

- `oathon validate <file> [--type t]` — strict parse + schema + semantic rules.
- `oathon verify <file> --keys keys.json [--type t]` — signed-object verification.
- `oathon verify <events.json> --chain` — event-chain verification.
- `oathon verify <closes.json> --segment-chain` — per-writer segment chain.
- `oathon verify <close.json> --type segment-close --events e.json --writer-auth a.json --keys k.json` — full segment verification.
