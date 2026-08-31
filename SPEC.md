# Oathon — Product and Protocol Specification v0.1

## 1. Mission

Oathon is the mandate-and-evidence layer for consequential autonomous AI-agent actions.

It produces three core artifact classes:

1. Mandates
2. Evidence
3. Evidence Packs and Incident Reconstructions

Oathon records and proves declared authority and recorded actions. It is not a policy-enforcement engine.

## 2. Product boundary

- **PROD-001** — Oathon MUST provide signed, versioned Mandates.
- **PROD-002** — Oathon MUST provide tamper-evident evidence chains.
- **PROD-003** — Oathon MUST produce independently verifiable evidence bundles.
- **PROD-004** — Oathon MUST produce Evidence Packs.
- **PROD-005** — Oathon MUST produce Incident Reconstructions.
- **PROD-006** — Oathon MUST NOT provide insurance advice.
- **PROD-007** — Oathon MUST NOT provide legal conclusions.
- **PROD-008** — Oathon MUST NOT become a general AI observability platform.
- **PROD-009** — Oathon MUST NOT implement runtime policy blocking in v0.1.
- **PROD-010** — Oathon MUST remain model-provider neutral in core packages.

## Note on server behavior

This public specification covers the protocol: cryptographic
objects, evidence semantics, the SDK, anchoring, and bundles —
everything an independent implementation or verifier needs.
Server behavior (the ingestion API, retention machinery, report
engine, and console) is specified in the private repository.

## 4. Organizations and keys

- **KEY-001** — Each organization MUST have one or more historical public signing keys.
- **KEY-002** — Private keys MUST be generated client-side.
- **KEY-003** — The server MUST never receive a private signing key.
- **KEY-004** — Public-key records MUST be append-only.
- **KEY-005** — Normal rotation MUST preserve cryptographic continuity by signing the transition with the previous active key.
- **KEY-006** — Administrative recovery MUST explicitly mark continuity as broken.
- **KEY-007** — Historical verification MUST remain possible after normal rotation or revocation.
- **KEY-008** — Losing the only private key MUST NOT cause historical public keys or historical signatures to be deleted.
- **KEY-009** — Segment-close records are signed by per-writer keys. A writer key MUST be generated client-side, MUST never be transmitted to the server, and MUST be certified by a writer-authorization record signed by an authorized organization signing key (CRYPTOGRAPHY.md §9b). The organization signing key SHOULD NOT be present in agent runtimes. *(Resolution of SC-2; ADR-012.)*
- **KEY-010** — The first organization signing key MUST be established by a self-signed key-genesis record (CRYPTOGRAPHY.md §9a) created client-side. The server MUST accept exactly one key-genesis record per organization. *(Resolution of NEW-2.)*

## 5. Mandate

A Mandate declares authority.

- **MANDATE-001** — A mandate MUST contain: mandate_id (UUIDv7), spec_version, organization identity, principal identity, agent identity, authority, oversight, validity, signature.
- **MANDATE-002** — Default principal identity SHOULD use a customer-scoped opaque subject_id. Email address MUST NOT be required.
- **MANDATE-003** — A principal MUST include a role or organizational capacity.
- **MANDATE-004** — An agent MUST include: agent_id, description, environment, model dependency descriptors where known.
- **MANDATE-005** — Permitted actions MUST use stable machine-readable action names. Each permitted action MUST declare its `evaluable_fields` (see MANDATE-014).
- **MANDATE-006** — Forbidden actions MUST use stable action names.
- **MANDATE-007** — Authority constraints MUST use the v0.1 deterministic constraint language.
- **MANDATE-008** — A mandate MUST be immutable once signed.
- **MANDATE-009** — A change MUST create a new mandate.
- **MANDATE-010** — A replacement mandate SHOULD identify supersedes.
- **MANDATE-011** — Revocation MUST use a signed append-only revocation record.
- **MANDATE-012** — Mandate validity times MUST use exact RFC 3339 UTC timestamps with millisecond precision: `YYYY-MM-DDTHH:MM:SS.sssZ`

## 6. Authority constraint language

Oathon v0.1 intentionally supports a small deterministic language.

Supported comparison operators: `eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `in`

Field references MUST use JSON Pointer.

Example:

```json
{
  "path": "/amount/minor_units",
  "op": "lte",
  "value": 20000
}
```

Currency:

```json
{
  "path": "/amount/currency",
  "op": "eq",
  "value": "EUR"
}
```

Human approval trigger:

```json
{
  "action": "issue_refund",
  "all": [
    { "path": "/amount/minor_units", "op": "gt", "value": 10000 },
    { "path": "/amount/currency", "op": "eq", "value": "EUR" }
  ]
}
```

A daily count constraint MAY use:

```json
{
  "op": "max_count_per_utc_day",
  "value": 50
}
```

- **MANDATE-013** — Unsupported or extension constraints MUST NOT silently be treated as satisfied. If they materially affect authority determination, determination MUST be ambiguous.
- **MANDATE-014** — Each permitted action MUST declare `evaluable_fields`: a list of JSON Pointers into the action's parameters. Every constraint `path` for that action MUST be a member of `evaluable_fields`. The SDK extracts exactly the values at those pointers into the event's `evaluation_metadata` (EVENT-009); all other action parameters are represented only by digest. *(Resolution of SC-1; ADR-011.)*
- **MANDATE-015** — The `in` operator's `value` MUST be a JSON array of scalars of a single JSON type. Membership is strict equality. Any other operand shape makes the constraint non-machine-evaluable (AUTH-006 applies). *(Resolution of AM-8.)*

## 7. Authority evaluation

- **AUTH-001** — A forbidden action is outside authority.
- **AUTH-002** — An action absent from permitted actions is outside authority unless the mandate explicitly defines another applicable rule.
- **AUTH-003** — Violation of a machine-evaluable hard constraint is outside.
- **AUTH-004** — If human approval is required, a matching approval MUST be linked by operation_id.
- **AUTH-005** — A required approval that is absent or denied makes subsequent execution outside.
- **AUTH-006** — Unknown or non-machine-evaluable authority semantics produce ambiguous.
- **AUTH-007** — Only fully satisfied supported rules may produce within.
- **AUTH-008** — Cross-writer aggregate constraints (e.g. `max_count_per_utc_day`) MUST order events by lexicographic `(occurred_at, event_id)`. The count determination is evidence-relative; where a boundary event's position depends on customer-controlled clocks, the determination for boundary events MUST be ambiguous. *(Resolution of AM-4.)*
- **AUTH-009** — Every authority determination is relative to an explicitly identified evidence set (the bundle manifest). If a required approval is absent from the evaluated set and the set's coverage is incomplete for the relevant period, the determination MUST be ambiguous, not outside. *(Resolution of NEW-5.)*

## 8. Evidence event model

- **EVENT-001** — Each event MUST contain: event_id (UUIDv7), spec_version, org_id, mandate_id where applicable, agent_id, writer_id, segment_id, sequence, operation_id where applicable, occurred_at, event_type, event-specific metadata, digests, capture_source, prev_hash, event_hash.
- **EVENT-002** — Supported event types: action_requested, action_executed, approval_requested, approval_granted, approval_denied, error, escalation, config_change.
- **EVENT-003** — JSON Schema MUST use event-type-specific validation so irrelevant required fields are not faked merely to satisfy one giant schema.
- **EVENT-004** — Raw action parameters MUST NOT be stored. The event stores a digest and safe structured metadata only. Safe structured metadata means exactly: the protocol-defined event fields and `evaluation_metadata` per EVENT-009. *(Clarified per SC-1.)*
- **EVENT-005** — Raw model prompts and outputs MUST NOT be stored.
- **EVENT-006** — occurred_at is customer-runtime-reported time. It MUST NOT automatically be represented as trusted third-party time.
- **EVENT-007** — The server MUST record ingested_at separately. ingested_at is server metadata and MUST NOT alter an already-created event hash.
- **EVENT-008** — operation_id MUST link related request, approval, execution, error, and escalation events where applicable.
- **EVENT-009** — `action_requested` and `action_executed` events MUST carry `evaluation_metadata`: an object mapping each JSON Pointer in the governing mandate's `evaluable_fields` for the action to the value found at that pointer (or `null` when absent). `evaluation_metadata` is part of the hashed event bytes. It MUST NOT contain any field outside the declared `evaluable_fields`. *(Resolution of SC-1; ADR-011.)*
- **EVENT-010** — Server-side metadata (`ingested_at`, storage identifiers) MUST live outside the event object and MUST NOT be merged into it. *(Resolution of AM-1; see CRYPTOGRAPHY.md §10.)*

## 9. Writer and segment model

The original "one chain per agent per day" model is replaced.

- **SEGMENT-001** — A writer is one logical serialization authority identified by persistent writer_id.
- **SEGMENT-002** — A segment belongs to one: org, agent, writer.
- **SEGMENT-003** — A writer MUST serialize durable event append operations.
- **SEGMENT-004** — Different concurrent agent replicas SHOULD use distinct writer_id values instead of coordinating one global agent chain.
- **SEGMENT-005** — A segment SHOULD be rotated: at UTC date transition while active; when reaching configured safe size limits; on explicit close; before continuing an old recovered segment when rotation policy requires it.
- **SEGMENT-006** — Clock regression MUST NOT cause a previously closed segment to be reopened.
- **SEGMENT-007** — Crash recovery MUST either safely continue the durable open segment or close/recover it without rewriting committed events.
- **SEGMENT-008** — Reports aggregate multiple writer segments for the same logical agent.
- **SEGMENT-009** — `writer_id` is a UUIDv7 minted at first spool creation and stored durably in the spool. A restarted process reuses the spooled writer_id; a lost spool means a new writer. Uniqueness scope is org + agent. *(Resolution of AM-3.)*
- **SEGMENT-010** — A writer's segment-close records MUST form a per-writer chain: each carries `segment_sequence` (starting at 0, increasing by exactly one) and `prev_segment_close_hash` (`null` for the writer's first segment; otherwise the anchor-input digest of the previous segment-close record). Verification MUST detect a missing closed segment within a writer's history. *(Resolution of NEW-3; ADR-014.)*

## 10. Capture sources

capture_source MUST be one of: `sdk_direct`, `otel`

- **CAPTURE-001** — Direct Oathon SDK instrumentation is the evidence-grade capture path.
- **CAPTURE-002** — OpenTelemetry integration is a convenience capture path.
- **CAPTURE-003** — OTel capture MUST NOT automatically be assumed complete.
- **CAPTURE-004** — A report MUST consider recorded coverage metadata before making absence claims from OTel-derived evidence.
- **CAPTURE-005** — Provider-specific adapters MUST remain outside core.

## 11. Python SDK

- **SDK-001** — The SDK MUST support initialization with: organization identity, local signing-key reference, local spool path, optional API endpoint.
- **SDK-002** — Offline operation MUST support: signing, hashing, chaining, durable local persistence, verification — without the Oathon API.
- **SDK-003** — Network communication MUST NOT be required before an event is durably committed locally in strict evidence mode.
- **SDK-004** — Network upload MUST occur asynchronously relative to normal action execution after durable local commit.
- **SDK-005** — Strict mode MUST expose local persistence failure.
- **SDK-006** — The SDK MUST NOT falsely report evidence success when durable recording failed.
- **SDK-007** — The local spool MUST be crash recoverable.
- **SDK-008** — Spool writes MUST use an atomic/durable design whose guarantees are documented and tested.
- **SDK-009** — Synchronization MUST be idempotent.
- **SDK-010** — The SDK MUST support explicit JSON and byte digest helpers.
- **SDK-011** — The SDK MUST provide `oathon verify`.
- **SDK-012** — The SDK MUST provide `oathon validate`.

## 15. Anchoring

- **ANCHOR-001** — v0.1 uses RFC 3161 timestamping.
- **ANCHOR-002** — RFC 9162 is not a v0.1 anchoring dependency.
- **ANCHOR-003** — A closed segment MAY be: `signed_unanchored`, `anchored`
- **ANCHOR-004** — TSA failure MUST NOT alter or reopen a signed segment.
- **ANCHOR-005** — Failed anchors MUST be retried.
- **ANCHOR-006** — A report MUST disclose unanchored relevant segments.
- **ANCHOR-007** — An anchor receipt MUST be verified before its segment is described as anchored.
- **ANCHOR-008** — Anchor receipts MUST be append-only.

## 16. Evidence bundle

- **BUNDLE-001** — Every generated report MUST have an associated machine-verifiable evidence bundle.
- **BUNDLE-002** — The bundle MUST contain relevant: mandate objects, revocation records, public-key history, evidence events, segment-close records, anchor receipts, provenance metadata, manifest.
- **BUNDLE-003** — The bundle MUST NOT contain raw customer payloads.
- **BUNDLE-004** — `oathon verify-bundle` MUST verify the bundle independently of the Oathon API.
- **BUNDLE-005** — A bundle manifest MUST list cryptographic digests of included artifacts.
