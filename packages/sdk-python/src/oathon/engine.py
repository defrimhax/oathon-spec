"""Server-side verification engine with honest incomplete-chain
representation (Phase 3; INV-014, API-013 shape).

Produces per-segment verification summaries for an agent. Gaps, breaks,
unclosed segments and missing segments in a writer's close chain are
REPORTED, never repaired or hidden.
"""

from __future__ import annotations

from typing import Any

from . import crypto
from .crypto import VerificationError
from .store import EvidenceStore
from .verify import verify_chain, verify_segment_close


def verification_report(store: EvidenceStore, org_id: str, agent_id: str) -> dict[str, Any]:
    segments = []
    for segment_id in store.segments_for_agent(org_id, agent_id):
        events = store.segment_events(org_id, segment_id)
        entry: dict[str, Any] = {
            "segment_id": segment_id,
            "writer_id": events[0]["writer_id"] if events else None,
            "event_count": len(events),
            "first_sequence": events[0]["sequence"] if events else None,
            "last_sequence": events[-1]["sequence"] if events else None,
        }
        try:
            verify_chain(events)
            entry["chain_status"] = "verified"
        except VerificationError as exc:
            entry["chain_status"] = "broken"
            entry["chain_error"] = str(exc)

        close = store.close(org_id, segment_id)
        if close is None:
            entry["closure_status"] = "open"
            entry["segment_sequence"] = None
        else:
            entry["segment_sequence"] = close["segment_sequence"]
            auth = _auth_for_close(store, org_id, close)
            if auth is None:
                entry["closure_status"] = "closed_unverified"
                entry["closure_error"] = "no covering writer authorization"
            else:
                try:
                    from .ingest import _keyset_with

                    verify_segment_close(close, events, auth, _keyset_with(store, auth))
                    entry["closure_status"] = "closed_verified"
                except VerificationError as exc:
                    entry["closure_status"] = "closed_unverified"
                    entry["closure_error"] = str(exc)
        if close is None:
            entry["anchor_status"] = "not_applicable_open"
        else:
            receipts = store.anchor_receipts(org_id, segment_id)
            # ANCHOR-003/007: only verified receipts make a segment anchored;
            # ANCHOR-006/REPORT-011: unanchored is disclosed, never hidden.
            entry["anchor_status"] = "anchored" if receipts else "signed_unanchored"
            entry["anchor_receipts"] = len(receipts)
        segments.append(entry)

    segments.sort(key=lambda s: (
        s["writer_id"] or "", s["segment_sequence"] if s["segment_sequence"] is not None else 1 << 60
    ))

    writers = _writer_continuity(store, org_id, {s["segment_id"] for s in segments})
    return {
        "org_id": org_id,
        "agent_id": agent_id,
        "segments": segments,
        "writers": writers,
        "complete": all(
            s["chain_status"] == "verified"
            and s["closure_status"] in ("closed_verified", "open")
            for s in segments
        ) and all(w["missing_segment_sequences"] == [] and w["continuity"] == "verified"
                  for w in writers),
    }


def _auth_for_close(store: EvidenceStore, org_id: str, close: dict) -> dict | None:
    for auth in store.writer_auths(org_id):
        if (
            auth["writer_id"] == close["writer_id"]
            and auth["agent_id"] == close["agent_id"]
            and auth["writer_key_id"] == close["signature"]["key_id"]
        ):
            return auth
    return None


def _writer_continuity(store: EvidenceStore, org_id: str, segment_ids) -> list[dict]:
    """Per-writer segment-close chain status (SEGMENT-010, INV-023).

    A missing segment_sequence or a broken prev link is reported as an
    explicit gap — never silently skipped (INV-014).
    """
    by_writer: dict[str, list[dict]] = {}
    for close in store.closes_for_org(org_id):
        if close["segment_id"] in segment_ids:
            by_writer.setdefault(close["writer_id"], []).append(close)

    writers = []
    for writer_id, closes in by_writer.items():
        closes.sort(key=lambda c: c["segment_sequence"])
        seqs = [c["segment_sequence"] for c in closes]
        missing = sorted(set(range(seqs[0], seqs[-1] + 1)) - set(seqs)) if seqs else []
        continuity = "verified"
        error = None
        prev_digest = None
        prev_seq = None
        for close in closes:
            if prev_seq is not None and close["segment_sequence"] != prev_seq + 1:
                continuity = "gap"
                error = f"segment_sequence jumps {prev_seq} -> {close['segment_sequence']}"
                break
            if close["segment_sequence"] == 0:
                if close["prev_segment_close_hash"] is not None:
                    continuity = "broken"
                    error = "first segment carries a prev_segment_close_hash"
                    break
            elif prev_digest is not None and close["prev_segment_close_hash"] != prev_digest:
                continuity = "broken"
                error = f"prev_segment_close_hash mismatch at segment_sequence {close['segment_sequence']}"
                break
            prev_digest = crypto.anchor_input_digest(close)
            prev_seq = close["segment_sequence"]
        writers.append({
            "writer_id": writer_id,
            "closed_segments": len(closes),
            "missing_segment_sequences": missing,
            "continuity": continuity,
            **({"continuity_error": error} if error else {}),
        })
    return writers
