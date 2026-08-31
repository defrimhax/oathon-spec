"""Sync tests: duplicate sync, conflicting ID,
out-of-order range, missing predecessor, retry after lost acknowledgement,
client reconnect, stale open segment, server restart. Plus idempotency-key
and all-or-nothing semantics (API-003..009)."""

import hashlib
import json

import pytest

from oathon import crypto, ids, keytools
from oathon.ingest import IngestError, batch_request_digest, ingest_batch
from oathon.engine import verification_report
from oathon.spool import EvidenceWriter
from oathon.store import EvidenceStore
from oathon.sync import SpoolSyncer
from oathon.verify import KeySet

ORG = "org_nordwind_test"
AGENT = "support-refund"


@pytest.fixture()
def org_key():
    seed = hashlib.sha256(b"WARRANT-INSECURE-TEST-KEY:org_key_1").digest()
    return crypto.private_key_from_seed(seed)


@pytest.fixture()
def rig(tmp_path, org_key, test_keys):
    """writer + auth + store + syncer wired with an in-process transport."""
    writer = EvidenceWriter(tmp_path / "spool", ORG, AGENT)
    auth = keytools.build_writer_authorization(
        org_private_key=org_key, org_id=ORG, agent_id=AGENT,
        writer_id=writer.writer_id, writer_public_key=writer.writer_public_key,
        not_before="2020-01-01T00:00:00.000Z", not_after="2030-01-01T00:00:00.000Z",
    )
    trusted = KeySet.from_json({
        test_keys["keys"]["org_key_1"]["key_id"]: test_keys["keys"]["org_key_1"]["public_key_b64u"],
    })
    store = EvidenceStore(trusted_org_keys=trusted)
    syncer = SpoolSyncer(tmp_path / "spool", lambda b: ingest_batch(store, b),
                         writer_authorization=auth)
    return writer, auth, store, syncer


def add_events(writer, n, start=0):
    return [
        writer.append(writer.build_event(
            event_type="error", metadata={"error_class": f"e{start + i}"}
        ))
        for i in range(n)
    ]


def stored_event_count(store):
    return len(store._state["events"].get(ORG, {}))


def test_happy_path_sync_and_report(rig):
    writer, _auth, store, syncer = rig
    add_events(writer, 3)
    writer.close_segment()
    outcome = syncer.sync()
    assert outcome["accepted_events"] == 3
    assert outcome["accepted_closes"] == 1
    report = verification_report(store, ORG, AGENT)
    assert report["complete"] is True
    assert report["segments"][0]["chain_status"] == "verified"
    assert report["segments"][0]["closure_status"] == "closed_verified"


def test_duplicate_sync_is_one_logical_copy(rig):
    writer, _auth, store, syncer = rig
    events = add_events(writer, 4)
    first = syncer.sync()
    assert first["accepted_events"] == 4
    outcome2 = syncer.sync()
    assert outcome2 == {"noop": True}
    # Identical resend after state loss = same idempotency key -> the ORIGINAL
    # outcome is replayed (API-004), and the store still holds one copy.
    (writer.spool / "sync-state.json").unlink()
    outcome3 = syncer.sync()
    assert outcome3 == first
    assert stored_event_count(store) == 4
    # A DIFFERENT request (fresh key) carrying already-stored events counts
    # them as duplicates instead (API-006 / SDK-009):
    batch = {"org_id": ORG, "writer_authorizations": [], "events": events,
             "segment_closes": [], "idempotency_key": "sha256:" + "A" * 43}
    outcome4 = ingest_batch(store, batch)
    assert outcome4["accepted_events"] == 0
    assert outcome4["duplicate_events"] == 4
    assert stored_event_count(store) == 4


def test_client_reconnect_after_state_loss(rig):
    writer, auth, store, _syncer = rig
    add_events(writer, 3)
    writer.close_segment()
    fresh = SpoolSyncer(writer.spool, lambda b: ingest_batch(store, b),
                        writer_authorization=auth)
    fresh.sync()
    # New syncer instance, no shared memory: state came only from disk.
    again = SpoolSyncer(writer.spool, lambda b: ingest_batch(store, b),
                        writer_authorization=auth)
    assert again.sync() == {"noop": True}
    assert stored_event_count(store) == 3


def test_retry_after_lost_acknowledgement(rig):
    writer, _auth, store, syncer = rig
    add_events(writer, 3)

    calls = {"n": 0}
    real_transport = syncer.transport

    def lossy(batch):
        outcome = real_transport(batch)  # server DID commit
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("ack lost on the wire")
        return outcome

    syncer.transport = lossy
    with pytest.raises(ConnectionError):
        syncer.sync()  # nothing acked client-side
    outcome = syncer.sync()  # retry: same content -> same idempotency key
    assert outcome["accepted_events"] == 3  # original outcome replayed (API-004)
    assert stored_event_count(store) == 3
    assert syncer.sync() == {"noop": True}


def test_conflicting_event_id_rejected_batch_untouched(rig):
    writer, _auth, store, syncer = rig
    events = add_events(writer, 2)
    syncer.sync()
    evil = json.loads(json.dumps(events[1]))
    evil["metadata"]["error_class"] = "forged"
    body = {k: v for k, v in evil.items() if k != "event_hash"}
    evil["event_hash"] = crypto.event_hash(body)
    batch = {"org_id": ORG, "writer_authorizations": [], "events": [evil],
             "segment_closes": []}
    batch["idempotency_key"] = batch_request_digest(batch)
    with pytest.raises(IngestError) as err:
        ingest_batch(store, batch)
    assert err.value.code == "evidence_conflict"  # API-007
    assert stored_event_count(store) == 2
    assert store.event(ORG, events[1]["event_id"])["metadata"]["error_class"] == "e1"


def test_missing_predecessor_rejects_whole_batch_with_range(rig):
    writer, _auth, store, _syncer = rig
    events = add_events(writer, 5)
    late = events[2:]  # starts at sequence 2, server has nothing
    batch = {"org_id": ORG, "writer_authorizations": [], "events": late,
             "segment_closes": []}
    batch["idempotency_key"] = batch_request_digest(batch)
    with pytest.raises(IngestError) as err:
        ingest_batch(store, batch)
    assert err.value.code == "missing_predecessor"  # API-009
    assert err.value.context["expected_sequence"] == 0
    assert err.value.context["received_sequence"] == 2
    assert err.value.context["affected_range"]["first_sequence"] == 2
    assert err.value.context["affected_range"]["last_sequence"] == 4
    assert stored_event_count(store) == 0  # API-008: nothing persisted


def test_out_of_order_events_rejected(rig):
    writer, _auth, store, _syncer = rig
    events = add_events(writer, 3)
    batch = {"org_id": ORG, "writer_authorizations": [],
             "events": [events[0], events[2], events[1]], "segment_closes": []}
    batch["idempotency_key"] = batch_request_digest(batch)
    with pytest.raises(IngestError) as err:
        ingest_batch(store, batch)
    assert err.value.code == "missing_predecessor"
    assert stored_event_count(store) == 0


def test_idempotency_key_reuse_with_different_bytes_conflicts(rig):
    writer, _auth, store, _syncer = rig
    events = add_events(writer, 2)
    batch1 = {"org_id": ORG, "writer_authorizations": [], "events": [events[0]],
              "segment_closes": []}
    batch1["idempotency_key"] = batch_request_digest(batch1)
    ingest_batch(store, batch1)
    batch2 = {"org_id": ORG, "writer_authorizations": [], "events": [events[1]],
              "segment_closes": [], "idempotency_key": batch1["idempotency_key"]}
    with pytest.raises(IngestError) as err:
        ingest_batch(store, batch2)
    assert err.value.code == "idempotency_conflict"  # API-005


def test_all_or_nothing_on_tampered_event(rig):
    writer, _auth, store, _syncer = rig
    events = add_events(writer, 3)
    tampered = json.loads(json.dumps(events[1]))
    tampered["metadata"]["error_class"] = "tampered"  # hash now wrong
    batch = {"org_id": ORG, "writer_authorizations": [],
             "events": [events[0], tampered, events[2]], "segment_closes": []}
    batch["idempotency_key"] = batch_request_digest(batch)
    with pytest.raises(IngestError) as err:
        ingest_batch(store, batch)
    assert err.value.code == "invalid_event"
    assert stored_event_count(store) == 0  # API-008


def test_stale_open_segment_incremental_sync(rig):
    writer, _auth, store, syncer = rig
    add_events(writer, 2)
    assert syncer.sync()["accepted_events"] == 2  # open segment syncs
    add_events(writer, 3, start=2)
    assert syncer.sync()["accepted_events"] == 3  # continues from acked tip
    close = writer.close_segment()
    outcome = syncer.sync()
    assert outcome["accepted_closes"] == 1
    report = verification_report(store, ORG, AGENT)
    assert report["segments"][0]["closure_status"] == "closed_verified"
    assert report["segments"][0]["event_count"] == close["event_count"] == 5


def test_append_to_closed_segment_rejected(rig):
    writer, _auth, store, syncer = rig
    events = add_events(writer, 2)
    writer.close_segment()
    syncer.sync()
    forged = dict(events[1])
    forged.pop("event_hash")
    forged["event_id"] = ids.uuid7()
    forged["sequence"] = 2
    forged["prev_hash"] = events[1]["event_hash"]
    forged["event_hash"] = crypto.event_hash(forged)
    batch = {"org_id": ORG, "writer_authorizations": [], "events": [forged],
             "segment_closes": []}
    batch["idempotency_key"] = batch_request_digest(batch)
    with pytest.raises(IngestError) as err:
        ingest_batch(store, batch)
    assert err.value.code == "evidence_conflict"
    assert err.value.context["reason"] == "segment already closed"


def test_unauthorized_close_rejected(tmp_path, org_key, test_keys):
    writer = EvidenceWriter(tmp_path / "spool", ORG, AGENT)
    add_events(writer, 1)
    writer.close_segment()
    trusted = KeySet.from_json({
        test_keys["keys"]["org_key_1"]["key_id"]: test_keys["keys"]["org_key_1"]["public_key_b64u"],
    })
    store = EvidenceStore(trusted_org_keys=trusted)
    syncer = SpoolSyncer(tmp_path / "spool", lambda b: ingest_batch(store, b),
                         writer_authorization=None)  # no auth registered
    with pytest.raises(IngestError) as err:
        syncer.sync()
    assert err.value.code == "unauthorized_close"
    assert stored_event_count(store) == 0


def test_server_restart_preserves_state(tmp_path, org_key, test_keys):
    writer = EvidenceWriter(tmp_path / "spool", ORG, AGENT)
    auth = keytools.build_writer_authorization(
        org_private_key=org_key, org_id=ORG, agent_id=AGENT,
        writer_id=writer.writer_id, writer_public_key=writer.writer_public_key,
        not_before="2020-01-01T00:00:00.000Z", not_after="2030-01-01T00:00:00.000Z",
    )
    trusted = KeySet.from_json({
        test_keys["keys"]["org_key_1"]["key_id"]: test_keys["keys"]["org_key_1"]["public_key_b64u"],
    })
    db = tmp_path / "server-state.json"
    store1 = EvidenceStore(path=db, trusted_org_keys=trusted)
    syncer1 = SpoolSyncer(tmp_path / "spool", lambda b: ingest_batch(store1, b),
                          writer_authorization=auth)
    add_events(writer, 3)
    writer.close_segment()
    syncer1.sync()
    report_before = verification_report(store1, ORG, AGENT)

    store2 = EvidenceStore(path=db, trusted_org_keys=trusted)  # restart
    report_after = verification_report(store2, ORG, AGENT)
    assert report_after == report_before
    # Post-restart, duplicate resend still deduplicates and new data flows.
    syncer2 = SpoolSyncer(tmp_path / "spool", lambda b: ingest_batch(store2, b),
                          writer_authorization=auth)
    (tmp_path / "spool" / "sync-state.json").unlink()
    outcome = syncer2.sync()
    # Identical resend -> idempotency record survived the restart and the
    # original outcome is replayed (API-004); still one logical copy.
    assert outcome["accepted_events"] == 3
    assert len(store2._state["events"][ORG]) == 3
    add_events(writer, 2, start=3)
    assert syncer2.sync()["accepted_events"] == 2
    assert len(store2._state["events"][ORG]) == 5
