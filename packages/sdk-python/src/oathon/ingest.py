"""Server-side batch ingestion (Phase 3 reference semantics).

Implements docs/sync-protocol.md: idempotency keys (API-003..005), event
identity (API-006/007, INV-008), all-or-nothing batches with gap rejection
identifying the affected contiguous range (API-008/009, ADR-013), server-side
re-verification (INV-002), and verified append-only close acceptance
(INV-006). Validation happens entirely before the single commit.
"""

from __future__ import annotations

from typing import Any

from . import crypto
from .crypto import VerificationError
from .store import EvidenceStore
from .validate import validate_object
from .verify import verify_event, verify_segment_close, verify_signed


class IngestError(Exception):
    def __init__(self, code: str, **context: Any):
        self.code = code
        self.context = context
        super().__init__(f"{code}: {context}")


def batch_request_digest(batch: dict[str, Any]) -> str:
    content = {k: v for k, v in batch.items() if k != "idempotency_key"}
    return crypto.digest_json(content)


def ingest_batch(store: EvidenceStore, batch: dict[str, Any]) -> dict[str, Any]:
    org_id = batch["org_id"]
    key = batch["idempotency_key"]
    request_digest = batch_request_digest(batch)

    # API-004/005 — idempotency-key semantics.
    prior = store.idempotency_record(key)
    if prior is not None:
        if prior["request_digest"] == request_digest:
            return prior["outcome"]
        raise IngestError("idempotency_conflict", idempotency_key=key)

    events = batch.get("events", [])
    closes = batch.get("segment_closes", [])
    auths = batch.get("writer_authorizations", [])

    # ---- validate everything before any commit (API-008) -----------------

    new_auths: list[dict] = []
    known_auths = {a["authorization_id"]: a for a in store.writer_auths(org_id)}
    for auth in auths:
        errors = validate_object(auth, "writer-authorization")
        if errors:
            raise IngestError("invalid_close", reason="bad writer authorization", errors=errors)
        try:
            verify_signed(auth, "writer-authorization", store.org_keyset(org_id))
        except VerificationError as exc:
            raise IngestError("unauthorized_close", reason=str(exc)) from exc
        if auth["org_id"] != org_id:
            raise IngestError("unauthorized_close", reason="authorization org mismatch")
        if auth["authorization_id"] not in known_auths:
            new_auths.append(auth)
            known_auths[auth["authorization_id"]] = auth

    new_events: list[dict] = []
    duplicates = 0
    pending_by_segment: dict[str, list[dict]] = {}
    for event in events:
        if event.get("org_id") != org_id:
            raise IngestError("invalid_event", reason="event org mismatch",
                              event_id=event.get("event_id"))
        errors = validate_object(event, "event")
        if errors:
            raise IngestError("invalid_event", event_id=event.get("event_id"), errors=errors)
        try:
            verify_event(event)  # INV-002: recompute the hash server-side
        except VerificationError as exc:
            raise IngestError("invalid_event", event_id=event["event_id"], reason=str(exc)) from exc

        existing = store.event(org_id, event["event_id"])
        if existing is not None:
            if existing["event_hash"] == event["event_hash"]:
                duplicates += 1  # API-006
                continue
            raise IngestError("evidence_conflict", event_id=event["event_id"])  # API-007
        pending_by_segment.setdefault(event["segment_id"], []).append(event)
        new_events.append(event)

    # API-009 / ADR-013 — each segment's new events must continue the tip.
    for segment_id, seg_events in pending_by_segment.items():
        tip = store.segment_tip(org_id, segment_id)
        if store.close(org_id, segment_id) is not None:
            raise IngestError("evidence_conflict", reason="segment already closed",
                              segment_id=segment_id)
        expected_seq = 0 if tip is None else tip["sequence"] + 1
        expected_prev = None if tip is None else tip["event_hash"]
        for event in seg_events:
            if event["sequence"] != expected_seq or event["prev_hash"] != expected_prev:
                raise IngestError(
                    "missing_predecessor",
                    segment_id=segment_id,
                    expected_sequence=expected_seq,
                    received_sequence=event["sequence"],
                    affected_range={
                        "segment_id": segment_id,
                        "first_sequence": seg_events[0]["sequence"],
                        "last_sequence": seg_events[-1]["sequence"],
                    },
                )
            expected_seq += 1
            expected_prev = event["event_hash"]

    new_closes: list[dict] = []
    duplicate_closes = 0
    for close in closes:
        if close.get("org_id") != org_id:
            raise IngestError("invalid_close", reason="close org mismatch")
        errors = validate_object(close, "segment-close")
        if errors:
            raise IngestError("invalid_close", segment_id=close.get("segment_id"), errors=errors)
        existing = store.close(org_id, close["segment_id"])
        if existing is not None:
            if crypto.digest_json(existing) == crypto.digest_json(close):
                duplicate_closes += 1
                continue
            raise IngestError("evidence_conflict", reason="conflicting close",
                              segment_id=close["segment_id"])
        chain = store.segment_events(org_id, close["segment_id"]) + \
            pending_by_segment.get(close["segment_id"], [])
        if not chain:
            raise IngestError("missing_predecessor", segment_id=close["segment_id"],
                              reason="close for unknown segment")
        auth = _covering_auth(known_auths.values(), close)
        if auth is None:
            raise IngestError("unauthorized_close", segment_id=close["segment_id"],
                              reason="no covering writer authorization")
        writer_pub = crypto.b64u_decode(auth["writer_public_key"])
        keyset_plus = _keyset_with(store, auth)
        try:
            verify_segment_close(close, chain, auth, keyset_plus)
        except VerificationError as exc:
            raise IngestError("invalid_close", segment_id=close["segment_id"],
                              reason=str(exc)) from exc
        del writer_pub
        new_closes.append(close)

    # ---- single atomic commit ---------------------------------------------

    outcome = {
        "accepted_events": len(new_events),
        "duplicate_events": duplicates,
        "accepted_closes": len(new_closes),
        "duplicate_closes": duplicate_closes,
        "accepted_authorizations": len(new_auths),
    }
    store.commit(
        org_id=org_id,
        new_events=new_events,
        new_closes=new_closes,
        new_auths=new_auths,
        idempotency_key=key,
        request_digest=request_digest,
        outcome=outcome,
    )
    return outcome


def _covering_auth(auths, close) -> dict | None:
    for auth in auths:
        if (
            auth["writer_id"] == close["writer_id"]
            and auth["agent_id"] == close["agent_id"]
            and auth["org_id"] == close["org_id"]
            and auth["writer_key_id"] == close["signature"]["key_id"]
        ):
            return auth
    return None


def _keyset_with(store: EvidenceStore, auth: dict):
    """Trusted org keys plus the writer key the authorization certifies."""
    from .verify import KeySet

    ks = KeySet(dict(store.org_keyset(auth["org_id"]).keys))
    ks.keys[auth["writer_key_id"]] = crypto.b64u_decode(auth["writer_public_key"])
    return ks
