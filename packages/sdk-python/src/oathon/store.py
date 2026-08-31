"""Reference evidence store for the Phase 3 sync/verification engine.

Append-only by construction (API-010/011): the only mutation path is
`commit()`, which appends new records. An optional path makes the store
restart-safe via atomic whole-state JSON persistence — sufficient for the
reference semantics; Postgres replaces it in Phase 4.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .verify import KeySet


class EvidenceStore:
    def __init__(self, path: str | Path | None = None, trusted_org_keys: KeySet | None = None):
        self.path = Path(path) if path else None
        self.trusted_org_keys = trusted_org_keys or KeySet()
        self._state: dict[str, Any] = {
            "events": {},        # org_id -> event_id -> event
            "segments": {},      # org_id -> segment_id -> [event_id, ...] in order
            "closes": {},        # org_id -> segment_id -> close record
            "writer_auths": {},  # org_id -> authorization_id -> record
            "idempotency": {},   # key -> {"request_digest": str, "outcome": dict}
        }
        if self.path and self.path.exists():
            self._state = json.loads(self.path.read_text())

    # -- reads -------------------------------------------------------------

    def event(self, org_id: str, event_id: str) -> dict | None:
        return self._state["events"].get(org_id, {}).get(event_id)

    def segment_events(self, org_id: str, segment_id: str) -> list[dict]:
        ids = self._state["segments"].get(org_id, {}).get(segment_id, [])
        return [self._state["events"][org_id][i] for i in ids]

    def segment_tip(self, org_id: str, segment_id: str) -> dict | None:
        events = self.segment_events(org_id, segment_id)
        return events[-1] if events else None

    def close(self, org_id: str, segment_id: str) -> dict | None:
        return self._state["closes"].get(org_id, {}).get(segment_id)

    def closes_for_org(self, org_id: str) -> list[dict]:
        return list(self._state["closes"].get(org_id, {}).values())

    def segments_for_agent(self, org_id: str, agent_id: str) -> list[str]:
        return [
            seg_id
            for seg_id, ids in self._state["segments"].get(org_id, {}).items()
            if ids and self._state["events"][org_id][ids[0]].get("agent_id") == agent_id
        ]

    def writer_auths(self, org_id: str) -> list[dict]:
        return list(self._state["writer_auths"].get(org_id, {}).values())

    def idempotency_record(self, key: str) -> dict | None:
        return self._state["idempotency"].get(key)

    def anchor_receipts(self, org_id: str, segment_id: str) -> list[dict]:
        """Verified anchor receipts for a segment (ANCHOR-003/008). The
        reference store has none; the Postgres store queries the anchors
        table."""
        return []

    def org_keyset(self, org_id: str) -> KeySet:
        """Trusted org signing keys. The reference store uses a static set;
        the Postgres store derives it from the org's key history."""
        return self.trusted_org_keys

    # -- single append-only mutation path -----------------------------------

    def commit(
        self,
        *,
        org_id: str,
        new_events: list[dict],
        new_closes: list[dict],
        new_auths: list[dict],
        idempotency_key: str,
        request_digest: str,
        outcome: dict,
    ) -> None:
        """Atomically append an accepted batch. Never updates existing rows."""
        events = self._state["events"].setdefault(org_id, {})
        segments = self._state["segments"].setdefault(org_id, {})
        closes = self._state["closes"].setdefault(org_id, {})
        auths = self._state["writer_auths"].setdefault(org_id, {})
        for event in new_events:
            assert event["event_id"] not in events, "append-only violation"
            events[event["event_id"]] = event
            segments.setdefault(event["segment_id"], []).append(event["event_id"])
        for close in new_closes:
            assert close["segment_id"] not in closes, "append-only violation"
            closes[close["segment_id"]] = close
        for auth in new_auths:
            auths[auth["authorization_id"]] = auth
        self._state["idempotency"][idempotency_key] = {
            "request_digest": request_digest,
            "outcome": outcome,
        }
        self._persist()

    def _persist(self) -> None:
        if not self.path:
            return
        tmp = self.path.with_suffix(".tmp")
        data = json.dumps(self._state, ensure_ascii=False).encode()
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
