"""Spool lifecycle tests (Phase 2: SDK-001..008, SEGMENT-005/006/009/010)."""

import datetime as dt
import hashlib
import json

import pytest

from oathon import crypto, keytools
from oathon.spool import EvidenceError, EvidenceWriter, verify_spool
from oathon.verify import KeySet


def ns(iso: str) -> int:
    return int(dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1e9)


class FakeClock:
    def __init__(self, start_iso: str):
        self.now = ns(start_iso)

    def __call__(self) -> int:
        self.now += 1_000_000  # +1ms per reading keeps timestamps advancing
        return self.now

    def jump_to(self, iso: str) -> None:
        self.now = ns(iso)


@pytest.fixture()
def mandate(vectors):
    return next(c for c in vectors["cases"] if c["name"] == "mandate-valid")["object"]


@pytest.fixture()
def org_key(test_keys):
    seed = hashlib.sha256(b"WARRANT-INSECURE-TEST-KEY:org_key_1").digest()
    return crypto.private_key_from_seed(seed)


def make_writer(tmp_path, clock=None):
    return EvidenceWriter(
        tmp_path / "spool", "org_nordwind_test", "support-refund", clock_ns=clock
    )


def auth_for(writer, org_key):
    return keytools.build_writer_authorization(
        org_private_key=org_key,
        org_id=writer.org_id,
        agent_id=writer.agent_id,
        writer_id=writer.writer_id,
        writer_public_key=writer.writer_public_key,
        not_before="2020-01-01T00:00:00.000Z",
        not_after="2030-01-01T00:00:00.000Z",
    )


def append_action(writer, mandate, op="01925000-0000-7000-8000-000000000500",
                  amount=7500, event_type="action_requested", status=None):
    params = {"amount": {"minor_units": amount, "currency": "EUR"}, "customer_ref": "c1"}
    return writer.append(writer.build_action_event(
        event_type=event_type, mandate=mandate, action="issue_refund",
        params=params, operation_id=op, status=status,
    ))


def test_offline_end_to_end(tmp_path, mandate, org_key, test_keys):
    clock = FakeClock("2026-09-02T08:30:00.000Z")
    writer = make_writer(tmp_path, clock)
    ev0 = append_action(writer, mandate)
    ev1 = append_action(writer, mandate, event_type="action_executed", status="succeeded")
    assert ev0["sequence"] == 0 and ev0["prev_hash"] is None
    assert ev1["sequence"] == 1 and ev1["prev_hash"] == ev0["event_hash"]
    assert ev0["evaluation_metadata"] == {"/amount/minor_units": 7500, "/amount/currency": "EUR"}

    close = writer.close_segment()
    assert close["event_count"] == 2
    assert close["segment_sequence"] == 0 and close["prev_segment_close_hash"] is None

    auth = auth_for(writer, org_key)
    keyset = KeySet.from_json({
        auth["signature"]["key_id"]: test_keys["keys"]["org_key_1"]["public_key_b64u"],
        writer.writer_key_id: crypto.b64u_encode(writer.writer_public_key),
    })
    summary = verify_spool(tmp_path / "spool", auth, keyset)
    assert summary["closed_segments"] == 1
    assert summary["closed_events"] == 2
    assert summary["close_signatures_verified"] is True


def test_writer_identity_persists_across_restart(tmp_path, mandate):
    writer1 = make_writer(tmp_path)
    append_action(writer1, mandate)
    writer2 = make_writer(tmp_path)
    assert writer2.writer_id == writer1.writer_id  # SEGMENT-009
    assert writer2.writer_key_id == writer1.writer_key_id
    ev = append_action(writer2, mandate)
    assert ev["sequence"] == 1  # continues the recovered open segment


def test_utc_day_rotation_chains_segments(tmp_path, mandate):
    clock = FakeClock("2026-09-02T23:59:00.000Z")
    writer = make_writer(tmp_path, clock)
    append_action(writer, mandate)
    clock.jump_to("2026-09-03T00:01:00.000Z")
    ev = append_action(writer, mandate)  # triggers SEGMENT-005 rotation
    assert ev["sequence"] == 0 and ev["prev_hash"] is None
    writer.close_segment()
    summary = verify_spool(tmp_path / "spool")
    assert summary["closed_segments"] == 2  # segment chain verified (INV-023)


def test_clock_regression_does_not_rotate_or_reopen(tmp_path, mandate):
    clock = FakeClock("2026-09-03T10:00:00.000Z")
    writer = make_writer(tmp_path, clock)
    append_action(writer, mandate)
    closed = writer.close_segment()
    clock.jump_to("2026-09-01T00:00:00.000Z")  # regression across two days
    ev = append_action(writer, mandate)
    # SEGMENT-006: closed segment stays closed; new events open a NEW segment.
    assert ev["segment_id"] != closed["segment_id"]
    assert ev["sequence"] == 0
    close_file = tmp_path / "spool" / "segments" / f"{closed['segment_id']}.close.json"
    assert json.loads(close_file.read_text()) == closed  # unchanged bytes


def test_append_after_close_goes_to_new_segment(tmp_path, mandate):
    writer = make_writer(tmp_path)
    ev_a = append_action(writer, mandate)
    writer.close_segment()
    old_log = (tmp_path / "spool" / "segments" / f"{ev_a['segment_id']}.log").read_bytes()
    ev_b = append_action(writer, mandate)
    assert ev_b["segment_id"] != ev_a["segment_id"]
    new_log = (tmp_path / "spool" / "segments" / f"{ev_a['segment_id']}.log").read_bytes()
    assert new_log == old_log  # closed segment log untouched (INV-001)


def test_duplicate_operation_creates_distinct_events(tmp_path, mandate):
    writer = make_writer(tmp_path)
    ev1 = append_action(writer, mandate)
    ev2 = append_action(writer, mandate)  # identical inputs, same operation_id
    assert ev1["event_id"] != ev2["event_id"]
    assert ev2["sequence"] == 1 and ev2["prev_hash"] == ev1["event_hash"]
    assert ev1["operation_id"] == ev2["operation_id"]  # linkage preserved (EVENT-008)


def test_absent_evaluable_field_recorded_as_null(tmp_path, mandate):
    writer = make_writer(tmp_path)
    ev = writer.append(writer.build_action_event(
        event_type="action_requested", mandate=mandate, action="issue_refund",
        params={"customer_ref": "c1"},  # no amount at all
        operation_id="01925000-0000-7000-8000-000000000501",
    ))
    assert ev["evaluation_metadata"] == {"/amount/minor_units": None, "/amount/currency": None}


def test_non_permitted_action_recorded_with_empty_metadata(tmp_path, mandate):
    """A forbidden/undeclared attempt is still evidence (Section D observed
    attempts); nothing is extracted because nothing was declared."""
    writer = make_writer(tmp_path)
    ev = writer.append(writer.build_action_event(
        event_type="action_requested", mandate=mandate, action="delete_customer_account",
        params={"target": "acct_1"}, operation_id="01925000-0000-7000-8000-000000000502",
    ))
    assert ev["evaluation_metadata"] == {}


def test_raw_params_never_stored(tmp_path, mandate):
    """EVENT-004/INV-010: the spool must contain digests, not the raw params."""
    writer = make_writer(tmp_path)
    secret = "SECRET-RAW-PARAM-XYZZY-4711"
    writer.append(writer.build_action_event(
        event_type="action_requested", mandate=mandate, action="issue_refund",
        params={"amount": {"minor_units": 7500, "currency": "EUR"}, "customer_ref": secret},
        operation_id="01925000-0000-7000-8000-000000000503",
    ))
    log_bytes = b"".join(
        p.read_bytes() for p in (tmp_path / "spool" / "segments").glob("*.log")
    )
    assert b"customer_ref" not in log_bytes
    assert secret.encode() not in log_bytes


def test_spool_refuses_foreign_org(tmp_path, mandate):
    make_writer(tmp_path)
    from oathon.spool import SpoolCorruptionError

    with pytest.raises(SpoolCorruptionError):
        EvidenceWriter(tmp_path / "spool", "org_other", "support-refund")
