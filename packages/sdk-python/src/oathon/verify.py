"""`oathon verify` core for static fixtures (Phase 1 scope).

Verifies: signed objects against a key set, event chains (hashes, prev
links, sequences — INV-003/004/007), segment-close records against writer
authorizations (INV-006), and per-writer segment-close chains (INV-023).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import crypto
from .crypto import VerificationError


@dataclass
class KeySet:
    """key_id → raw public key bytes, e.g. loaded from a key-history fixture."""

    keys: dict[str, bytes] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict[str, str]) -> "KeySet":
        ks = cls()
        for key_id, public_key_b64u in data.items():
            raw = crypto.b64u_decode(public_key_b64u)
            expected = crypto.key_id_for_public_key(raw)
            if expected != key_id:
                raise VerificationError(
                    f"key set entry {key_id} does not match its public key ({expected})"
                )
            ks.keys[key_id] = raw
        return ks

    def public_key(self, key_id: str) -> bytes:
        if key_id not in self.keys:
            raise VerificationError(f"unknown key_id: {key_id}")
        return self.keys[key_id]


def verify_signed(obj: dict[str, Any], object_type: str, keyset: KeySet) -> None:
    """Verify a signed object of the given type using its declared key_id."""
    domain = crypto.SIGN_DOMAINS.get(object_type)
    if domain is None:
        raise VerificationError(f"not a signed object type: {object_type}")
    sig = obj.get("signature")
    if not isinstance(sig, dict) or "key_id" not in sig:
        raise VerificationError("missing signature.key_id")
    crypto.verify_object(obj, domain, keyset.public_key(sig["key_id"]))


def verify_event(event: dict[str, Any]) -> None:
    """Recompute the event hash and compare (INV-007)."""
    stored = event.get("event_hash")
    if not isinstance(stored, str):
        raise VerificationError("missing event_hash")
    body = {k: v for k, v in event.items() if k != "event_hash"}
    computed = crypto.event_hash(body)
    if computed != stored:
        raise VerificationError(
            f"event_hash mismatch: stored {stored}, computed {computed}"
        )


def verify_chain(events: list[dict[str, Any]]) -> None:
    """Verify a full intra-segment chain (INV-003, INV-004, INV-007)."""
    if not events:
        raise VerificationError("empty chain")
    segment_id = events[0].get("segment_id")
    writer_id = events[0].get("writer_id")
    prev_hash: str | None = None
    for i, event in enumerate(events):
        verify_event(event)
        if event.get("segment_id") != segment_id:
            raise VerificationError(f"event {i}: segment_id differs within chain")
        if event.get("writer_id") != writer_id:
            raise VerificationError(f"event {i}: writer_id differs within chain (INV-005)")
        if event.get("sequence") != i + (events[0].get("sequence") or 0):
            raise VerificationError(
                f"event {i}: sequence {event.get('sequence')} breaks +1 ordering (INV-004)"
            )
        if i == 0:
            if event.get("sequence") == 0 and event.get("prev_hash") is not None:
                raise VerificationError("genesis event must have prev_hash null (INV-003)")
            prev_hash = event.get("event_hash")
            continue
        if event.get("prev_hash") != prev_hash:
            raise VerificationError(
                f"event {i}: prev_hash does not reference predecessor (INV-003)"
            )
        prev_hash = event.get("event_hash")


def verify_segment_close(
    close: dict[str, Any],
    events: list[dict[str, Any]],
    writer_auth: dict[str, Any],
    keyset: KeySet,
    at: str | None = None,
) -> None:
    """Verify a segment-close record end to end (INV-006 as amended).

    Chains: close signature → writer key → writer authorization → org key.
    `at` (protocol timestamp) checks the authorization window against the
    close's signed_at when omitted.
    """
    verify_signed(writer_auth, "writer-authorization", keyset)

    writer_key_raw = crypto.b64u_decode(writer_auth["writer_public_key"])
    writer_key_id = crypto.key_id_for_public_key(writer_key_raw)
    if writer_auth.get("writer_key_id") != writer_key_id:
        raise VerificationError("writer_key_id does not match writer_public_key")

    sig = close.get("signature", {})
    if sig.get("key_id") != writer_key_id:
        raise VerificationError("segment close not signed by the authorized writer key")
    for bind in ("org_id", "agent_id", "writer_id"):
        if close.get(bind) != writer_auth.get(bind):
            raise VerificationError(f"writer authorization {bind} does not cover this segment")
    when = at or sig.get("signed_at")
    if not (writer_auth["not_before"] <= str(when) <= writer_auth["not_after"]):
        raise VerificationError("segment close signed outside the authorization window")
    crypto.verify_object(close, crypto.DOMAIN_SEGMENT, writer_key_raw)

    verify_chain(events)
    if close.get("first_event_hash") != events[0].get("event_hash"):
        raise VerificationError("first_event_hash does not match chain")
    if close.get("last_event_hash") != events[-1].get("event_hash"):
        raise VerificationError("last_event_hash does not match chain")
    if close.get("event_count") != len(events):
        raise VerificationError("event_count does not match chain length")
    if close.get("first_sequence") != events[0].get("sequence"):
        raise VerificationError("first_sequence does not match chain")
    if close.get("last_sequence") != events[-1].get("sequence"):
        raise VerificationError("last_sequence does not match chain")
    for event in events:
        if event.get("segment_id") != close.get("segment_id"):
            raise VerificationError("chain events belong to a different segment")


def verify_segment_sequence(closes: list[dict[str, Any]]) -> None:
    """Verify a writer's segment-close chain (SEGMENT-010, INV-023)."""
    if not closes:
        raise VerificationError("empty segment-close chain")
    writer_id = closes[0].get("writer_id")
    prev_digest: str | None = None
    for i, close in enumerate(closes):
        if close.get("writer_id") != writer_id:
            raise VerificationError(f"close {i}: writer_id differs within chain")
        expected_seq = (closes[0].get("segment_sequence") or 0) + i
        if close.get("segment_sequence") != expected_seq:
            raise VerificationError(
                f"close {i}: segment_sequence {close.get('segment_sequence')} "
                f"breaks +1 ordering (INV-023)"
            )
        if i == 0:
            if close.get("segment_sequence") == 0 and close.get("prev_segment_close_hash") is not None:
                raise VerificationError("first segment must have prev_segment_close_hash null")
        elif close.get("prev_segment_close_hash") != prev_digest:
            raise VerificationError(
                f"close {i}: prev_segment_close_hash does not reference predecessor (INV-023)"
            )
        prev_digest = crypto.anchor_input_digest(close)


def mandate_status(mandate: dict[str, Any], at: str) -> str:
    """'active', 'not_yet_valid' or 'expired' at protocol timestamp `at`.

    Lexicographic comparison is exact because CRYPTO-006 fixes one format.
    """
    validity = mandate.get("validity", {})
    if at < validity.get("not_before", ""):
        return "not_yet_valid"
    if at >= validity.get("not_after", "~"):
        return "expired"
    return "active"
