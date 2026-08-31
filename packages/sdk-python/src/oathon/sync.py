"""Client synchronization engine (SDK-004/009, docs/sync-protocol.md).

Reads the local spool, sends everything unacknowledged through an injectable
transport, and records acknowledgements in <spool>/sync-state.json (atomic
writes). Retries are safe by construction: the idempotency key is derived
from batch content and event identity is deduplicated server-side, so
repeated synchronization yields exactly one logical copy. Sync never mutates
spool evidence (INV-018).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from .jsonutil import loads_strict
from .ingest import batch_request_digest

Transport = Callable[[dict[str, Any]], dict[str, Any]]


class SyncError(Exception):
    pass


class SpoolSyncer:
    def __init__(self, spool_dir: str | Path, transport: Transport,
                 writer_authorization: dict[str, Any] | None = None):
        self.spool = Path(spool_dir)
        self.transport = transport
        self.writer_authorization = writer_authorization
        self._state_path = self.spool / "sync-state.json"
        writer_info = loads_strict((self.spool / "writer.json").read_bytes())
        self.org_id = writer_info["org_id"]

    # -- acked-position state ----------------------------------------------

    def _load_state(self) -> dict[str, Any]:
        if self._state_path.exists():
            return loads_strict(self._state_path.read_bytes())
        return {"acked_sequences": {}, "acked_closes": [], "auth_sent": False}

    def _save_state(self, state: dict[str, Any]) -> None:
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_bytes(json.dumps(state, ensure_ascii=False).encode())
        os.replace(tmp, self._state_path)

    # -- spool reading (never mutates; INV-018) ----------------------------

    def _read_spool(self) -> tuple[dict[str, list[dict]], dict[str, dict]]:
        segments_dir = self.spool / "segments"
        events_by_segment: dict[str, list[dict]] = {}
        closes: dict[str, dict] = {}
        for log in sorted(segments_dir.glob("*.log")):
            events = [loads_strict(line) for line in log.read_bytes().split(b"\n") if line]
            if events:
                events_by_segment[log.stem] = events
            close_path = segments_dir / f"{log.stem}.close.json"
            if close_path.exists():
                closes[log.stem] = loads_strict(close_path.read_bytes())
        return events_by_segment, closes

    # -- sync ---------------------------------------------------------------

    def sync(self) -> dict[str, Any]:
        """One synchronization pass. Returns the transport outcome summary.
        Safe to call repeatedly and after any failure."""
        state = self._load_state()
        events_by_segment, closes = self._read_spool()

        pending_events: list[dict] = []
        for segment_id, events in sorted(events_by_segment.items()):
            acked = state["acked_sequences"].get(segment_id, -1)
            pending_events.extend(e for e in events if e["sequence"] > acked)
        pending_closes = [
            close for segment_id, close in sorted(closes.items())
            if segment_id not in state["acked_closes"]
        ]
        auths = []
        if self.writer_authorization is not None and (pending_closes or not state["auth_sent"]):
            auths = [self.writer_authorization]

        if not pending_events and not pending_closes and not auths:
            return {"noop": True}

        batch = {
            "org_id": self.org_id,
            "writer_authorizations": auths,
            "events": pending_events,
            "segment_closes": pending_closes,
        }
        batch["idempotency_key"] = batch_request_digest(batch)
        outcome = self.transport(batch)  # may raise; nothing acked in that case

        for event in pending_events:
            seg = event["segment_id"]
            state["acked_sequences"][seg] = max(
                state["acked_sequences"].get(seg, -1), event["sequence"]
            )
        for close in pending_closes:
            if close["segment_id"] not in state["acked_closes"]:
                state["acked_closes"].append(close["segment_id"])
        if auths:
            state["auth_sent"] = True
        self._save_state(state)
        return outcome
