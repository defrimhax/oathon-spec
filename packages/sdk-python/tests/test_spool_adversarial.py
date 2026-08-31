"""Spool adversarial tests: process kill, corrupted
tail, concurrent threads, wrong signing key, disk failure, multi-open-segment
corruption. TEST-005/TEST-006."""

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from oathon import crypto, keytools
from oathon.crypto import VerificationError
from oathon.spool import (
    EvidenceError,
    EvidenceWriter,
    SpoolCorruptionError,
    verify_spool,
)
from oathon.verify import KeySet, verify_segment_close


@pytest.fixture()
def mandate(vectors):
    return next(c for c in vectors["cases"] if c["name"] == "mandate-valid")["object"]


def make_writer(tmp_path):
    return EvidenceWriter(tmp_path / "spool", "org_nordwind_test", "support-refund")


def append_error(writer, n=0):
    return writer.append(writer.build_event(
        event_type="error", metadata={"error_class": f"e{n}"}
    ))


def open_log(tmp_path) -> Path:
    logs = [
        p for p in (tmp_path / "spool" / "segments").glob("*.log")
        if not p.with_name(p.stem + ".close.json").exists()
    ]
    assert len(logs) == 1
    return logs[0]


def test_torn_tail_is_truncated_and_chain_continues(tmp_path):
    writer = make_writer(tmp_path)
    ev0 = append_error(writer, 0)
    ev1 = append_error(writer, 1)
    log = open_log(tmp_path)
    with open(log, "ab") as fh:
        fh.write(b'{"event_id":"0192-torn-partial')  # torn final line, no newline

    recovered = make_writer(tmp_path)
    events = recovered.read_segment(ev0["segment_id"])
    assert [e["event_hash"] for e in events] == [ev0["event_hash"], ev1["event_hash"]]
    ev2 = append_error(recovered, 2)
    assert ev2["sequence"] == 2 and ev2["prev_hash"] == ev1["event_hash"]
    verify_spool(tmp_path / "spool")


def test_corrupted_middle_line_fails_loudly(tmp_path):
    writer = make_writer(tmp_path)
    append_error(writer, 0)
    append_error(writer, 1)
    append_error(writer, 2)
    log = open_log(tmp_path)
    lines = log.read_bytes().split(b"\n")
    lines[1] = b'{"not":"an event"}'
    log.write_bytes(b"\n".join(lines))
    with pytest.raises(SpoolCorruptionError):
        make_writer(tmp_path)


def test_mutated_middle_event_fails_loudly(tmp_path):
    writer = make_writer(tmp_path)
    append_error(writer, 0)
    append_error(writer, 1)
    append_error(writer, 2)
    log = open_log(tmp_path)
    lines = log.read_bytes().split(b"\n")
    middle = json.loads(lines[1])
    middle["metadata"]["error_class"] = "tampered"
    lines[1] = json.dumps(middle, separators=(",", ":"), sort_keys=True).encode()
    log.write_bytes(b"\n".join(lines))
    with pytest.raises(SpoolCorruptionError):
        make_writer(tmp_path)


def test_process_kill_during_append(tmp_path):
    """Real SIGKILL mid-write: recovery must yield an intact verified chain."""
    spool = tmp_path / "spool"
    child = subprocess.Popen(
        [sys.executable, str(Path(__file__).parent / "spool_child.py"), str(spool)],
        stdout=subprocess.PIPE, text=True,
    )
    committed = 0
    deadline = time.time() + 20
    while committed < 50 and time.time() < deadline:
        line = child.stdout.readline()
        if line.strip().isdigit():
            committed = int(line)
    os.kill(child.pid, signal.SIGKILL)
    child.wait()
    assert committed >= 50, "child never reached 50 committed events"

    recovered = EvidenceWriter(spool, "org_nordwind_test", "support-refund")
    summary = verify_spool(spool)
    total = sum(summary["open_segments"].values()) + summary["closed_events"]
    # Everything acknowledged before the kill must have survived (ADR-006);
    # at most the final unacknowledged append may exceed the count.
    assert total >= committed
    ev = append_error(recovered, 999)  # spool remains usable after recovery
    assert ev["sequence"] == total
    verify_spool(spool)


def test_concurrent_threads_serialize_into_one_chain(tmp_path):
    writer = make_writer(tmp_path)
    threads = [
        threading.Thread(target=lambda i=i: [append_error(writer, i) for _ in range(25)])
        for i in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    events = writer.read_segment(open_log(tmp_path).stem)
    assert len(events) == 200
    assert [e["sequence"] for e in events] == list(range(200))  # INV-004
    verify_spool(tmp_path / "spool")


def test_fsync_failure_raises_and_spool_survives(tmp_path, monkeypatch):
    writer = make_writer(tmp_path)
    append_error(writer, 0)
    real_fsync = os.fsync

    def failing_fsync(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(EvidenceError, match="durable append failed"):
        append_error(writer, 1)  # INV-019: failure exposed, not disguised
    monkeypatch.setattr(os, "fsync", real_fsync)

    recovered = make_writer(tmp_path)
    events = recovered.read_segment(open_log(tmp_path).stem)
    assert len(events) >= 1 and events[0]["metadata"]["error_class"] == "e0"
    append_error(recovered, 2)
    verify_spool(tmp_path / "spool")


def test_wrong_signing_key_fails_segment_verification(tmp_path, test_keys):
    writer = make_writer(tmp_path)
    append_error(writer, 0)
    close = writer.close_segment()

    org_seed = hashlib.sha256(b"WARRANT-INSECURE-TEST-KEY:org_key_1").digest()
    org_key = crypto.private_key_from_seed(org_seed)
    other_priv, other_pub, other_key_id = keytools.generate_signing_key()
    # Authorization covers a DIFFERENT writer key than the one that signed.
    bad_auth = keytools.build_writer_authorization(
        org_private_key=org_key, org_id=writer.org_id, agent_id=writer.agent_id,
        writer_id=writer.writer_id, writer_public_key=other_pub,
        not_before="2020-01-01T00:00:00.000Z", not_after="2030-01-01T00:00:00.000Z",
    )
    keyset = KeySet.from_json({
        crypto.key_id_for_public_key(crypto.public_key_bytes(org_key)):
            test_keys["keys"]["org_key_1"]["public_key_b64u"],
        other_key_id: crypto.b64u_encode(other_pub),
        writer.writer_key_id: crypto.b64u_encode(writer.writer_public_key),
    })
    events = writer.read_segment(close["segment_id"])
    with pytest.raises(VerificationError):
        verify_segment_close(close, events, bad_auth, keyset)


def test_multiple_open_segments_refused(tmp_path):
    writer = make_writer(tmp_path)
    append_error(writer, 0)
    seg_dir = tmp_path / "spool" / "segments"
    first_log = open_log(tmp_path)
    rogue = seg_dir / "01925000-9999-7000-8000-000000000000.log"
    rogue.write_bytes(first_log.read_bytes())
    with pytest.raises(SpoolCorruptionError, match="INV-005"):
        make_writer(tmp_path)
