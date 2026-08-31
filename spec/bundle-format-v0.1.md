# Oathon evidence-bundle format v0.1

Added to the public specification after a SPECIFICATION GAP finding: SPEC.md
§16 and PROVENANCE.md defined what a bundle contains and guarantees, but not
the file layout an independent verifier needs. This document is normative
for v0.1 bundles.

## Layout

A bundle is a directory (or a zip of one) containing:

| File | Content |
|---|---|
| `manifest.json` | see below |
| `mandates.json` | JSON array of signed mandate objects |
| `revocations.json` | JSON array of signed revocation records |
| `key_records.json` | JSON array of `{"record_type": "genesis"\|"transition", "record": {...}}`, in registration order |
| `writer_auths.json` | JSON array of signed writer-authorization records |
| `events.jsonl` | one evidence event per line; each line is the event's RFC 8785 canonical JSON (so `line == JCS(event)` byte-for-byte), UTF-8, `\n`-terminated |
| `segment_closes.json` | JSON array of signed segment-close records |
| `anchors.json` | JSON array of `{"segment_id", "tsa_url", "receipt_b64"}` (base64 of the raw RFC 3161 response DER); may be empty |
| `assertions.json` | the report's assertion list (see PROVENANCE.md) |
| `report.html` | the rendered report (a view, never the root of trust) |
| `tsa_certs/*.pem` | optional TSA certificate material for receipt verification |

## Manifest

```json
{
  "bundle_id": "...",
  "report_id": "...",
  "created_at": "<protocol timestamp>",
  "spec_version": "0.1",
  "artifacts": { "<relative path>": "<digest>", ... }
}
```

Every file in the bundle except `manifest.json` itself MUST appear in
`artifacts`. Each digest is the **byte digest** of the file's exact bytes
per CRYPTOGRAPHY.md §12: `sha256:` + base64url-no-pad of
`SHA-256("WARRANT-DIGEST-BYTES-V0.1" ‖ 0x00 ‖ file_bytes)` (BUNDLE-005).

## Verification order (BUNDLE-004)

1. Every manifest digest matches its file's bytes; every listed file exists.
2. Walk `key_records.json`: the first record MUST be a self-signed genesis
   (CRYPTO §9a); each normal transition MUST verify against the previous
   key (§9); `continuity = "administrative-recovery"` records verify
   against their own new key and MUST be reported as continuity breaks
   (KEY-006). All historical keys are retained (INV-012).
3. Verify every mandate, revocation and writer authorization against the
   accumulated org key set (§6–§9b).
4. Group events by `segment_id`; verify every event hash (§10) and each
   segment's chain (INV-003/004/005).
5. Verify each segment close: signature by the writer key certified by a
   covering authorization (org/agent/writer match, window covers
   `signature.signed_at`), and exact chain consistency (§13). A close whose
   segment's events or authorization are absent is reported unverified —
   disclosed, never hidden (INV-014).
6. Where a writer's closes form a contiguous run from `segment_sequence` 0,
   verify the per-writer chain via the §14 anchor-input digest links
   (SEGMENT-010, INV-023); otherwise report the run as partial.
7. Optionally verify anchor receipts against `tsa_certs/` (RFC 3161 token
   verification; verifiers MAY mark this NOT COVERED).
8. Every assertion's `source_refs` MUST resolve to bundle artifacts by id
   (`events/<event_id>`, `mandates/<mandate_id>`, `segments/<segment_id>`,
   `revocations/<id>`, `authorizations/<id>`) or carry a `derived:` marker
   (INV-020).
