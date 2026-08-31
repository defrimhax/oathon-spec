# Oathon — Cryptographic Protocol v0.1

This document defines the exact cryptographic interpretation of Oathon v0.1 artifacts. Implementations MUST conform byte-for-byte.

## 1. Algorithms

- **CRYPTO-001** — Hash algorithm: SHA-256
- **CRYPTO-002** — Signature algorithm: Ed25519
- **CRYPTO-003** — JSON canonicalization: RFC 8785 JSON Canonicalization Scheme.
- **CRYPTO-004** — Text encoding: UTF-8 without BOM.
- **CRYPTO-005** — Binary-to-text encoding for signatures, hashes, and raw public keys: RFC 4648 base64url alphabet without = padding.
- **CRYPTO-006** — All protocol timestamps (`occurred_at`, `signed_at`, `opened_at`, `closed_at`, `effective_at`, `revoked_at`, validity bounds, and any other protocol-defined time field) MUST use exact RFC 3339 UTC with millisecond precision: `YYYY-MM-DDTHH:MM:SS.sssZ`. *(Resolution of AM-6; generalizes MANDATE-012.)*

## 2. JSON restrictions

Before canonicalization:

- duplicate object keys MUST be rejected
- NaN MUST be rejected
- Infinity MUST be rejected
- negative Infinity MUST be rejected
- protocol-defined monetary values MUST NOT use floating point
- protocol-defined integers requiring exact interoperability MUST remain in the safe integer domain unless represented as strings by schema

Money MUST be represented as:

```json
{
  "minor_units": 20000,
  "currency": "EUR"
}
```

where minor_units is an integer.

## 3. Digest string

A SHA-256 digest is encoded as:

```
sha256:<base64url-no-padding>
```

The decoded digest MUST contain exactly 32 bytes.

## 4. Key identifiers

An Ed25519 public key consists of its 32 raw public-key bytes. Wherever a public key appears in a JSON field (e.g. `new_public_key`, `public_key`), those 32 bytes are carried per CRYPTO-005 (base64url, no padding). *(Clarified per AM-5.)*

The key identifier is computed over the raw 32 bytes:

```
"ed25519:" + BASE64URL_NO_PAD( SHA256(raw_public_key_bytes) )
```

A key_id mismatch MUST fail verification.

## 5. Domain separation

The following ASCII byte strings, including the terminating zero byte, are normative:

```
WARRANT-MANDATE-SIGN-V0.1\0
WARRANT-REVOCATION-SIGN-V0.1\0
WARRANT-KEY-TRANSITION-SIGN-V0.1\0
WARRANT-EVENT-HASH-V0.1\0
WARRANT-SEGMENT-SIGN-V0.1\0
WARRANT-DIGEST-JSON-V0.1\0
WARRANT-DIGEST-BYTES-V0.1\0
WARRANT-ANCHOR-INPUT-V0.1\0
WARRANT-KEY-GENESIS-SIGN-V0.1\0
WARRANT-WRITER-AUTH-SIGN-V0.1\0
```

The two-character sequence `\0` above is notation for a single 0x00 byte — it is not the literal characters backslash and zero. *(Reworded per N-2. The last two domain strings were added by the freeze resolutions of NEW-2 and SC-2.)*

### Protocol identifier note

The wire protocol retains its original `WARRANT-*-V0.1` domain-separation
identifiers for compatibility; the product brand is Oathon. These byte
strings are frozen protocol bytes (INV-022): changing them would invalidate
every existing signature, hash, and committed test vector. A future spec
version MAY introduce `OATHON-*` identifiers via the INV-022 process
(ADR-017).

## 6. Generic signed-object construction

Signed objects contain:

```json
"signature": {
  "alg": "Ed25519",
  "key_id": "...",
  "signed_at": "2026-08-31T10:15:30.123Z",
  "value": "..."
}
```

To calculate the signing input:

1. deep-copy the complete object
2. remove only signature.value
3. retain signature.alg
4. retain signature.key_id
5. retain signature.signed_at
6. validate the resulting object against the corresponding signing schema
7. JCS-canonicalize the result
8. UTF-8 encode the canonical JSON
9. prepend the object-type domain bytes
10. Ed25519-sign the resulting byte sequence

Pseudocode:

```
function signing_input(object, DOMAIN):
    x = deep_copy(object)
    delete x.signature.value
    canonical = JCS(x)
    return DOMAIN || UTF8(canonical)
```

Verification MUST reconstruct the same bytes.

Unknown fields are forbidden in v0.1 signed objects: every signing schema uses `additionalProperties: false`, and validation MUST reject an object carrying a field its schema does not define. Extension happens only via a new `spec_version`. *(Resolution of AM-2.)*

## 7. Mandate signatures

Mandates use: `WARRANT-MANDATE-SIGN-V0.1\0`

The signature MUST cover every mandate field except signature.value.

## 8. Revocation signatures

Mandate revocation records use: `WARRANT-REVOCATION-SIGN-V0.1\0`

A revocation record MUST contain at minimum:

- revocation_id
- spec_version
- org_id
- mandate_id
- revoked_at
- reason
- signature

*(Field list added by NEW-4 resolution.)*

Revocation is an append-only signed record. A mandate MUST NOT be deleted as a substitute for revocation.

## 9. Key transition signatures

Normal key rotation MUST create a key-transition record containing at least:

- transition_id
- org_id
- old_key_id
- new_key_id
- new_public_key
- effective_at
- reason
- signature

The transition MUST be signed by the old active key.

If the old key is unavailable because of loss or compromise, administrative recovery MAY register a replacement, but the new record MUST be marked:

```
continuity = "administrative-recovery"
```

A report MUST NOT represent such transition as cryptographically continuous.

## 9a. Key genesis record

The first organization signing key is established by a self-signed key-genesis record containing at least:

- genesis_id
- spec_version
- org_id
- key_id
- public_key
- created_at
- signature

It uses: `WARRANT-KEY-GENESIS-SIGN-V0.1\0`

The record is signed by the key it introduces (`signature.key_id` MUST equal `key_id`). The server MUST accept exactly one key-genesis record per organization; all later keys arrive via key transitions (§9) or administrative recovery. *(Resolution of NEW-2.)*

## 9b. Writer authorization record

Segment-close records are signed by per-writer keys, not by the organization signing key. A writer key is certified by a writer-authorization record containing at least:

- authorization_id
- spec_version
- org_id
- agent_id
- writer_id
- writer_key_id
- writer_public_key
- not_before
- not_after
- signature

It uses: `WARRANT-WRITER-AUTH-SIGN-V0.1\0`

The record MUST be signed by an authorized organization signing key. Verification of a segment close chains: segment-close signature → writer key → writer-authorization record → organization key history. A segment close signed by a writer key without a covering authorization (org, agent, writer_id, validity window all matching) MUST fail verification. Writer private keys are generated client-side and MUST NOT be transmitted to the server. *(Resolution of SC-2; ADR-012.)*

## 10. Event hash

An event stored before event_hash calculation contains prev_hash. prev_hash therefore appears exactly once in the hash input.

For the genesis event:

```json
"prev_hash": null
```

For later events:

```json
"prev_hash": "sha256:..."
```

Calculation:

```
function event_hash(event_without_event_hash):
    canonical = JCS(event_without_event_hash)
    bytes =
        ASCII("WARRANT-EVENT-HASH-V0.1") ||
        0x00 ||
        UTF8(canonical)
    return SHA256(bytes)
```

After calculation, the encoded hash is stored as event_hash. The implementation MUST NOT append prev_hash a second time.

Hash coverage is total: every field present in the event object except `event_hash` is covered by the hash. Server-side metadata (`ingested_at`, storage identifiers) MUST live outside the event object and MUST NOT be merged into it before or after hashing. *(Resolution of AM-1.)*

## 11. Structured JSON digest helper

For a JSON value:

```
digest_json(value):
    validate JCS-compatible JSON
    canonical = JCS(value)
    return SHA256(
        ASCII("WARRANT-DIGEST-JSON-V0.1") ||
        0x00 ||
        UTF8(canonical)
    )
```

## 12. Byte digest helper

For arbitrary bytes:

```
digest_bytes(value):
    return SHA256(
        ASCII("WARRANT-DIGEST-BYTES-V0.1") ||
        0x00 ||
        value
    )
```

The SDK MUST require the caller to distinguish JSON from bytes. It MUST NOT guess serialization based on a language-native object.

## 13. Segment closure

A segment-close record MUST contain at minimum:

- spec_version
- segment_id
- org_id
- agent_id
- writer_id
- segment_sequence
- prev_segment_close_hash
- first_event_hash
- last_event_hash
- event_count
- first_sequence
- last_sequence
- opened_at
- closed_at
- signature

It uses: `WARRANT-SEGMENT-SIGN-V0.1\0`

The segment-close record is signed by the writer key certified per §9b. `segment_sequence` starts at 0 per writer and increases by exactly one; `prev_segment_close_hash` is `null` for the writer's first segment and otherwise the anchor-input digest (§14) of the writer's previous segment-close record. *(Resolutions of SC-2 and NEW-3.)*

## 14. RFC 3161 anchor input

The externally timestamped datum is NOT the entire event history. It is a SHA-256 digest of the complete signed segment-close record.

Calculation:

```
anchor_input_digest(segment_close_with_signature):
    canonical = JCS(segment_close_with_signature)
    return SHA256(
        ASCII("WARRANT-ANCHOR-INPUT-V0.1") ||
        0x00 ||
        UTF8(canonical)
    )
```

The RFC 3161 messageImprint MUST correspond exactly to this SHA-256 digest. The request SHOULD request inclusion of the TSA certificate material needed for later verification. Requests SHOULD include a fresh cryptographically random nonce; when a nonce was sent, the response MUST contain an equal nonce or verification fails. *(Resolution of AM-7.)*

The implementation MUST:

- verify the returned status
- verify the message imprint
- verify the nonce when used
- verify the timestamp token signature
- retain the raw timestamp response
- retain relevant certificate material returned with it

Multiple receipts for the same segment MAY exist. They MUST be append-only.

## 15. Normative test vectors

Phase 1 MUST generate committed cross-implementation vectors for:

- valid mandate signature
- modified mandate field
- modified signing metadata
- wrong public key
- valid revocation
- valid key rotation
- genesis event
- second chained event
- event mutation
- predecessor mutation
- Unicode-containing event
- structured digest
- byte digest
- segment signature
- anchor input digest
- key genesis record
- writer authorization record
- segment-close chain (two segments linked by prev_segment_close_hash)
- writer authorization mismatch (wrong writer_id / expired window)

Test vectors MUST contain exact expected canonical bytes where practical, expected hashes, signatures, and verification outcomes.
