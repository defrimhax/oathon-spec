"""Verification-engine tests: incomplete chains, gaps, and breaks are
REPRESENTED, never repaired or hidden (INV-014, Phase 3 deliverable)."""

import hashlib
import json

import pytest

from oathon import crypto, keytools
from oathon.engine import verification_report
from oathon.ingest import ingest_batch
from oathon.spool import EvidenceWriter
from oathon.store import EvidenceStore
from oathon.sync import SpoolSyncer
from oathon.verify import KeySet

ORG = "org_nordwind_test"
AGENT = "support-refund"


@pytest.fixture()
def synced(tmp_path, test_keys):
    """Three closed, chained segments synced into a store."""
    seed = hashlib.sha256(b"WARRANT-INSECURE-TEST-KEY:org_key_1").digest()
    org_key = crypto.private_key_from_seed(seed)
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
    for i in range(3):
        for j in range(2):
            writer.append(writer.build_event(
                event_type="error", metadata={"error_class": f"s{i}e{j}"}
            ))
        writer.close_segment()
        syncer.sync()
    return writer, store


def test_complete_history_reports_complete(synced):
    _writer, store = synced
    report = verification_report(store, ORG, AGENT)
    assert report["complete"] is True
    assert [s["segment_sequence"] for s in report["segments"]] == [0, 1, 2]
    assert report["writers"][0]["continuity"] == "verified"
    assert report["writers"][0]["missing_segment_sequences"] == []


def test_missing_middle_segment_is_exposed(synced):
    """Simulates server-side deletion of a whole segment (SECURITY.md §7):
    the writer close chain makes it visible (INV-023 / NEW-3 resolution)."""
    _writer, store = synced
    org_closes = store._state["closes"][ORG]
    org_segments = store._state["segments"][ORG]
    victim = next(s for s, c in org_closes.items() if c["segment_sequence"] == 1)
    del org_closes[victim]
    for event_id in org_segments.pop(victim):
        del store._state["events"][ORG][event_id]

    report = verification_report(store, ORG, AGENT)
    assert report["complete"] is False
    writer_entry = report["writers"][0]
    assert writer_entry["missing_segment_sequences"] == [1]
    assert writer_entry["continuity"] == "gap"


def test_broken_prev_link_is_exposed(synced):
    _writer, store = synced
    org_closes = store._state["closes"][ORG]
    victim = next(c for c in org_closes.values() if c["segment_sequence"] == 2)
    victim["prev_segment_close_hash"] = crypto.digest_string(b"\x00" * 32)

    report = verification_report(store, ORG, AGENT)
    assert report["complete"] is False
    assert report["writers"][0]["continuity"] == "broken"
    # The mutated close also fails its own signature verification:
    seg = next(s for s in report["segments"] if s["segment_sequence"] == 2)
    assert seg["closure_status"] == "closed_unverified"


def test_tampered_stored_event_breaks_chain_status(synced):
    _writer, store = synced
    some_event = next(iter(store._state["events"][ORG].values()))
    some_event["metadata"]["error_class"] = "tampered-in-db"

    report = verification_report(store, ORG, AGENT)
    assert report["complete"] is False
    broken = [s for s in report["segments"] if s["chain_status"] == "broken"]
    assert len(broken) == 1 and "mismatch" in broken[0]["chain_error"]


def test_open_segment_is_reported_open_not_hidden(synced):
    writer, store = synced
    writer.append(writer.build_event(event_type="error", metadata={"error_class": "x"}))
    syncer = SpoolSyncer(writer.spool, lambda b: ingest_batch(store, b))
    syncer.sync()
    report = verification_report(store, ORG, AGENT)
    open_segments = [s for s in report["segments"] if s["closure_status"] == "open"]
    assert len(open_segments) == 1
    assert report["complete"] is True  # open-but-verified is not a defect


def test_missing_authorization_reports_unverified_not_verified(synced):
    """INV-013 spirit: absence of proof must never present as proof."""
    _writer, store = synced
    store._state["writer_auths"][ORG] = {}
    report = verification_report(store, ORG, AGENT)
    assert report["complete"] is False
    assert all(s["closure_status"] == "closed_unverified" for s in report["segments"])
