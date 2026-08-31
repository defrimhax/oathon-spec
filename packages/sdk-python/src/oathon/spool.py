"""Durable local evidence spool (Phase 2; SDK-001..008, ADR-006).

Design (SDK-008, documented and tested):

- Layout:  <spool>/writer.json            writer identity (SEGMENT-009)
           <spool>/writer_key.json        writer private seed, mode 0600
           <spool>/segments/<id>.log      append-only JSONL, one canonical
                                          event per line, fsync per append
           <spool>/segments/<id>.close.json  signed close record (atomic
                                          tmp+rename+dir-fsync)
- Durability boundary (ADR-006): append_event returns only after the event
  line is written and fsynced. A failure raises EvidenceError (INV-019).
- Crash model: appends are sequential and fsynced, so only the final line
  can be torn. Recovery truncates a torn/invalid *tail* line; any invalid
  line that is NOT the last one means real corruption and recovery fails
  loudly (SpoolCorruptionError) instead of rewriting history (INV-001).
- Rotation (SEGMENT-005): on append when the UTC day advanced past the open
  segment's first event; on explicit close; never on clock regression
  (SEGMENT-006 — a regressed clock keeps the current segment open).
- Closes are signed with the spool's writer key (KEY-009) and chained per
  writer via segment_sequence / prev_segment_close_hash (SEGMENT-010).
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Callable

from . import crypto, ids
from .jsonutil import StrictJSONError, loads_strict
from .pointer import resolve_pointer
from .validate import validate_object
from .verify import verify_event


class EvidenceError(Exception):
    """Durable evidence recording failed (INV-019: never disguised)."""


class SpoolCorruptionError(Exception):
    """The spool contains damage recovery must not silently repair (INV-001)."""


class ClosedSegmentError(Exception):
    """Attempted append to a closed segment (SEGMENT-006/INV-001)."""


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write_json(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    data = json.dumps(obj, ensure_ascii=False, indent=2).encode()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def extract_evaluation_metadata(mandate: dict[str, Any], action: str, params: Any) -> dict[str, Any]:
    """EVENT-009: exactly the declared evaluable_fields, absent → null.

    An action with no permitted-action entry (e.g. a forbidden or undeclared
    attempt) has no declared evaluable_fields, so nothing is extracted — but
    the attempt itself MUST still be recordable as evidence (REPORTING §4
    Section D observed attempts; the evaluator classifies it outside)."""
    for entry in mandate.get("authority", {}).get("permitted_actions", []):
        if entry.get("action") == action:
            return {
                pointer: resolve_pointer(params, pointer)
                for pointer in entry.get("evaluable_fields", [])
            }
    return {}


class EvidenceWriter:
    """One writer (SEGMENT-001/003): serializes durable appends for one
    org+agent spool. Thread-safe; concurrent replicas use separate spools
    (SEGMENT-004)."""

    def __init__(
        self,
        spool_dir: str | Path,
        org_id: str,
        agent_id: str,
        clock_ns: Callable[[], int] | None = None,
        strict: bool = True,
    ) -> None:
        self.spool = Path(spool_dir)
        self.org_id = org_id
        self.agent_id = agent_id
        self.clock_ns = clock_ns or ids.now_ns
        self.strict = strict
        self._lock = threading.Lock()
        self._segments_dir = self.spool / "segments"
        self._segments_dir.mkdir(parents=True, exist_ok=True)
        self._load_or_mint_identity()
        self._open_segment_id: str | None = None
        self._last_event: dict[str, Any] | None = None
        self._open_fh = None
        self._recover()

    # -- identity ----------------------------------------------------------

    def _load_or_mint_identity(self) -> None:
        writer_file = self.spool / "writer.json"
        key_file = self.spool / "writer_key.json"
        if writer_file.exists():
            info = loads_strict(writer_file.read_bytes())
            if info["org_id"] != self.org_id or info["agent_id"] != self.agent_id:
                raise SpoolCorruptionError(
                    "spool belongs to a different org/agent; refusing to reuse writer_id"
                )
            self.writer_id = info["writer_id"]
            seed = bytes.fromhex(loads_strict(key_file.read_bytes())["seed_hex"])
        else:
            self.writer_id = ids.uuid7(self.clock_ns())
            seed = os.urandom(32)
            _atomic_write_json(key_file, {
                "WARNING": "writer private key seed — never transmit (KEY-009)",
                "seed_hex": seed.hex(),
            })
            _atomic_write_json(writer_file, {
                "writer_id": self.writer_id,
                "org_id": self.org_id,
                "agent_id": self.agent_id,
                "created_at": ids.protocol_timestamp(self.clock_ns()),
            })
        self._writer_key = crypto.private_key_from_seed(seed)
        self.writer_public_key = crypto.public_key_bytes(self._writer_key)
        self.writer_key_id = crypto.key_id_for_public_key(self.writer_public_key)

    # -- recovery ----------------------------------------------------------

    def _log_path(self, segment_id: str) -> Path:
        return self._segments_dir / f"{segment_id}.log"

    def _close_path(self, segment_id: str) -> Path:
        return self._segments_dir / f"{segment_id}.close.json"

    def _read_log(self, segment_id: str, repair_tail: bool) -> list[dict[str, Any]]:
        """Read and verify a segment log. With repair_tail, a torn/invalid
        FINAL line is truncated away; damage earlier in the file raises."""
        path = self._log_path(segment_id)
        raw = path.read_bytes()
        events: list[dict[str, Any]] = []
        offset = 0
        lines = raw.split(b"\n")
        # A well-formed log ends with b"\n" → final split element is empty.
        body_lines = lines[:-1] if lines and lines[-1] == b"" else lines
        for i, line in enumerate(body_lines):
            is_last = i == len(body_lines) - 1
            try:
                event = loads_strict(line)
                verify_event(event)
                expected_seq = len(events)
                if event.get("sequence") != expected_seq:
                    raise SpoolCorruptionError(
                        f"sequence {event.get('sequence')} != {expected_seq}"
                    )
                if expected_seq == 0:
                    if event.get("prev_hash") is not None:
                        raise SpoolCorruptionError("genesis prev_hash not null")
                elif event.get("prev_hash") != events[-1]["event_hash"]:
                    raise SpoolCorruptionError("prev_hash chain break")
            except (StrictJSONError, ValueError, crypto.VerificationError, SpoolCorruptionError) as exc:
                if is_last and repair_tail:
                    fd = os.open(path, os.O_WRONLY)
                    try:
                        os.ftruncate(fd, offset)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    return events
                raise SpoolCorruptionError(
                    f"segment {segment_id} line {i}: {exc}"
                ) from exc
            events.append(event)
            offset += len(line) + 1
        return events

    def _recover(self) -> None:
        open_segments = [
            p.stem for p in self._segments_dir.glob("*.log")
            if not self._close_path(p.stem).exists()
        ]
        if len(open_segments) > 1:
            raise SpoolCorruptionError(
                f"multiple open segments {open_segments}: writer serialization violated (INV-005)"
            )
        if not open_segments:
            return
        segment_id = open_segments[0]
        events = self._read_log(segment_id, repair_tail=True)
        if not events:
            # Nothing durably committed in this segment; safe to discard.
            self._log_path(segment_id).unlink()
            return
        self._open_segment_id = segment_id
        self._last_event = events[-1]

    # -- segment chain state ----------------------------------------------

    def _closed_records(self) -> list[dict[str, Any]]:
        closes = [
            loads_strict(p.read_bytes())
            for p in sorted(self._segments_dir.glob("*.close.json"))
        ]
        closes.sort(key=lambda c: c["segment_sequence"])
        return closes

    def _next_segment_link(self) -> tuple[int, str | None]:
        closes = self._closed_records()
        if not closes:
            return 0, None
        last = closes[-1]
        return last["segment_sequence"] + 1, crypto.anchor_input_digest(last)

    # -- event building ----------------------------------------------------

    def build_action_event(
        self,
        *,
        event_type: str,
        mandate: dict[str, Any],
        action: str,
        params: Any,
        operation_id: str,
        status: str | None = None,
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        """Build (without committing) an action_requested/executed event with
        EVENT-009 extraction and an action_params digest (EVENT-004)."""
        metadata: dict[str, Any] = {"action": action}
        if status is not None:
            metadata["status"] = status
        return self._event_body(
            event_type=event_type,
            mandate_id=mandate["mandate_id"],
            operation_id=operation_id,
            metadata=metadata,
            evaluation_metadata=extract_evaluation_metadata(mandate, action, params),
            digests={"action_params": crypto.digest_json(params)},
            occurred_at=occurred_at,
        )

    def build_event(
        self,
        *,
        event_type: str,
        metadata: dict[str, Any],
        mandate_id: str | None = None,
        operation_id: str | None = None,
        digests: dict[str, str] | None = None,
        occurred_at: str | None = None,
        capture_source: str = "sdk_direct",
    ) -> dict[str, Any]:
        """Build a non-action event (approval/error/escalation/config_change)."""
        body = self._event_body(
            event_type=event_type,
            mandate_id=mandate_id,
            operation_id=operation_id,
            metadata=metadata,
            evaluation_metadata=None,
            digests=digests or {},
            occurred_at=occurred_at,
        )
        body["capture_source"] = capture_source
        return body

    def _event_body(self, *, event_type, mandate_id, operation_id, metadata,
                    evaluation_metadata, digests, occurred_at) -> dict[str, Any]:
        ts = self.clock_ns()
        body: dict[str, Any] = {
            "event_id": ids.uuid7(ts),
            "spec_version": "0.1",
            "org_id": self.org_id,
            "agent_id": self.agent_id,
            "writer_id": self.writer_id,
            "occurred_at": occurred_at or ids.protocol_timestamp(ts),
            "event_type": event_type,
            "metadata": metadata,
            "digests": digests,
            "capture_source": "sdk_direct",
        }
        if mandate_id is not None:
            body["mandate_id"] = mandate_id
        if operation_id is not None:
            body["operation_id"] = operation_id
        if evaluation_metadata is not None:
            body["evaluation_metadata"] = evaluation_metadata
        return body

    # -- append ------------------------------------------------------------

    def append(self, partial_event: dict[str, Any]) -> dict[str, Any]:
        """Durably commit an event built by build_*: assigns segment,
        sequence, prev_hash and event_hash, validates, appends + fsyncs."""
        with self._lock:
            self._maybe_rotate_locked()
            if self._open_segment_id is None:
                self._open_segment_id = ids.uuid7(self.clock_ns())
                self._last_event = None
            event = dict(partial_event)
            event["segment_id"] = self._open_segment_id
            event["writer_id"] = self.writer_id
            if self._last_event is None:
                event["sequence"] = 0
                event["prev_hash"] = None
            else:
                event["sequence"] = self._last_event["sequence"] + 1
                event["prev_hash"] = self._last_event["event_hash"]
            event["event_hash"] = crypto.event_hash(
                {k: v for k, v in event.items() if k != "event_hash"}
            )
            errors = validate_object(event, "event")
            if errors:
                raise EvidenceError(f"refusing to commit invalid event: {errors}")
            line = crypto.canonicalize(event) + b"\n"
            path = self._log_path(self._open_segment_id)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.write(fd, line)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError as exc:
                if self.strict:
                    raise EvidenceError(f"durable append failed: {exc}") from exc
                raise
            self._last_event = event
            return event

    # -- rotation and close ------------------------------------------------

    def _maybe_rotate_locked(self) -> None:
        if self._open_segment_id is None or self._last_event is None:
            return
        opened_day = ids.utc_day(self._first_event_locked()["occurred_at"])
        today = ids.utc_day(ids.protocol_timestamp(self.clock_ns()))
        # SEGMENT-005 rotation on UTC day advance; SEGMENT-006: regression
        # (today < opened_day) must not rotate or reopen anything.
        if today > opened_day:
            self._close_locked()

    def _first_event_locked(self) -> dict[str, Any]:
        events = self._read_log(self._open_segment_id, repair_tail=False)
        return events[0]

    def close_segment(self) -> dict[str, Any] | None:
        """Explicitly close the open segment (signed close record), if any."""
        with self._lock:
            return self._close_locked()

    def _close_locked(self) -> dict[str, Any] | None:
        if self._open_segment_id is None:
            return None
        segment_id = self._open_segment_id
        events = self._read_log(segment_id, repair_tail=False)
        if not events:
            self._log_path(segment_id).unlink()
            self._open_segment_id = None
            self._last_event = None
            return None
        segment_sequence, prev_digest = self._next_segment_link()
        record = {
            "spec_version": "0.1",
            "segment_id": segment_id,
            "org_id": self.org_id,
            "agent_id": self.agent_id,
            "writer_id": self.writer_id,
            "segment_sequence": segment_sequence,
            "prev_segment_close_hash": prev_digest,
            "first_event_hash": events[0]["event_hash"],
            "last_event_hash": events[-1]["event_hash"],
            "event_count": len(events),
            "first_sequence": events[0]["sequence"],
            "last_sequence": events[-1]["sequence"],
            "opened_at": events[0]["occurred_at"],
            "closed_at": ids.protocol_timestamp(self.clock_ns()),
            "signature": {
                "alg": "Ed25519",
                "key_id": self.writer_key_id,
                "signed_at": ids.protocol_timestamp(self.clock_ns()),
            },
        }
        signed = crypto.sign_object(record, crypto.DOMAIN_SEGMENT, self._writer_key)
        errors = validate_object(signed, "segment-close")
        if errors:
            raise EvidenceError(f"refusing to write invalid close record: {errors}")
        _atomic_write_json(self._close_path(segment_id), signed)
        self._open_segment_id = None
        self._last_event = None
        return signed

    # -- offline verification (SDK-002) ------------------------------------

    def read_segment(self, segment_id: str) -> list[dict[str, Any]]:
        return self._read_log(segment_id, repair_tail=False)


def verify_spool(
    spool_dir: str | Path,
    writer_auth: dict[str, Any] | None = None,
    keyset=None,
) -> dict[str, Any]:
    """Offline verification of a whole spool (SDK-002).

    Verifies every closed segment's chain, close record (against writer_auth
    + keyset when provided), the per-writer segment-close chain (INV-023),
    and the open segment's chain. Returns a summary dict; raises on failure.
    """
    from .verify import verify_chain, verify_segment_close, verify_segment_sequence

    segments_dir = Path(spool_dir) / "segments"
    closes = [
        loads_strict(p.read_bytes()) for p in sorted(segments_dir.glob("*.close.json"))
    ]
    closes.sort(key=lambda c: c["segment_sequence"])
    open_logs = [
        p.stem for p in segments_dir.glob("*.log")
        if not (segments_dir / f"{p.stem}.close.json").exists()
    ]

    def read_events(segment_id: str) -> list[dict[str, Any]]:
        raw = (segments_dir / f"{segment_id}.log").read_bytes()
        return [loads_strict(line) for line in raw.split(b"\n") if line]

    for close in closes:
        events = read_events(close["segment_id"])
        if writer_auth is not None and keyset is not None:
            verify_segment_close(close, events, writer_auth, keyset)
        else:
            verify_chain(events)
    if closes:
        verify_segment_sequence(closes)
    open_counts = {}
    for segment_id in open_logs:
        events = read_events(segment_id)
        if events:
            verify_chain(events)
        open_counts[segment_id] = len(events)
    return {
        "closed_segments": len(closes),
        "closed_events": sum(c["event_count"] for c in closes),
        "open_segments": open_counts,
        "close_signatures_verified": writer_auth is not None and keyset is not None,
    }
