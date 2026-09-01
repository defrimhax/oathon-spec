"""Regenerate the refund-agent sample bundle (INSECURE demo keys, synthetic
data). Uses only the public SDK. Run from the repository root:

    .venv/bin/python samples/refund-agent/generate.py

Overwrites samples/refund-agent/ bundle files and sample-bundle.zip.
"""

import datetime
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from oathon import crypto, ids, keytools
from oathon.bundle import write_bundle
from oathon.spool import EvidenceWriter

OUT = Path(__file__).resolve().parent
ORG = "org_sample_refunds"
AGENT = "refund-agent"
BASE = datetime.datetime(2026, 9, 1, 9, 0, tzinfo=datetime.timezone.utc)


def ts(minutes: int) -> str:
    t = BASE + datetime.timedelta(minutes=minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def main() -> None:
    org_seed = hashlib.sha256(b"OATHON-SAMPLE-KEY:refund-agent-demo").digest()
    org_key = crypto.private_key_from_seed(org_seed)
    org_pub = crypto.public_key_bytes(org_key)

    genesis = keytools.build_key_genesis(
        ORG, org_key, int(BASE.timestamp() * 1e9))
    mandate = crypto.sign_object({
        "mandate_id": ids.uuid7(), "spec_version": "0.1",
        "organization": {"org_id": ORG, "display_name": "Sample Co"},
        "principal": {"subject_id": "subj_cfo", "role": "CFO"},
        "agent": {"agent_id": AGENT,
                  "description": "Customer refund agent (sample)",
                  "environment": "sample"},
        "authority": {
            "permitted_actions": [{"action": "issue_refund",
                                   "evaluable_fields": ["/amount/minor_units",
                                                        "/amount/currency"]}],
            "forbidden_actions": ["delete_customer_account"],
            "constraints": [{"action": "issue_refund",
                             "path": "/amount/minor_units", "op": "lte",
                             "value": 20000}],
            "approval_triggers": [{"action": "issue_refund",
                                   "all": [{"path": "/amount/minor_units",
                                            "op": "gt", "value": 10000}]}]},
        "oversight": {"review_cadence": "weekly"},
        "validity": {"not_before": "2026-01-01T00:00:00.000Z",
                     "not_after": "2027-01-01T00:00:00.000Z"},
        "signature": {"alg": "Ed25519",
                      "key_id": crypto.key_id_for_public_key(org_pub),
                      "signed_at": ts(0)},
    }, crypto.DOMAIN_MANDATE, org_key)

    with tempfile.TemporaryDirectory() as tmp:
        clock = {"ns": int(BASE.timestamp() * 1e9)}
        writer = EvidenceWriter(Path(tmp) / "spool", ORG, AGENT,
                                clock_ns=lambda: clock["ns"])

        def refund(minute, amount, op_id, *, approve=None, execute=True):
            params = {"amount": {"minor_units": amount, "currency": "EUR"},
                      "customer_ref": "sample-customer"}
            writer.append(writer.build_action_event(
                event_type="action_requested", mandate=mandate,
                action="issue_refund", params=params, operation_id=op_id,
                occurred_at=ts(minute)))
            if approve is not None:
                writer.append(writer.build_event(
                    event_type="approval_requested",
                    mandate_id=mandate["mandate_id"], operation_id=op_id,
                    metadata={"action": "issue_refund"},
                    occurred_at=ts(minute + 1)))
                writer.append(writer.build_event(
                    event_type="approval_granted" if approve else "approval_denied",
                    mandate_id=mandate["mandate_id"], operation_id=op_id,
                    metadata={"action": "issue_refund",
                              "approver_ref": "subj_finance_lead"},
                    occurred_at=ts(minute + 3)))
            if execute:
                writer.append(writer.build_action_event(
                    event_type="action_executed", mandate=mandate,
                    action="issue_refund", params=params, operation_id=op_id,
                    status="succeeded", occurred_at=ts(minute + 5)))

        refund(10, 7500, ids.uuid7())                     # clean flow, within
        refund(30, 75000, ids.uuid7())                    # over limit, no approval
        refund(50, 15000, ids.uuid7(), approve=False)     # denied, then executed
        close = writer.close_segment()
        auth = keytools.build_writer_authorization(
            org_private_key=org_key, org_id=ORG, agent_id=AGENT,
            writer_id=writer.writer_id,
            writer_public_key=writer.writer_public_key,
            not_before="2026-01-01T00:00:00.000Z",
            not_after="2027-01-01T00:00:00.000Z")

        events = writer.read_segment(close["segment_id"])
        assertions = [{
            "assertion_id": f"S-{i + 1:04d}",
            "classification": "OBSERVED",
            "text": f"Sample evidence event {e['event_type']} at {e['occurred_at']}.",
            "source_refs": [f"events/{e['event_id']}"],
            "verification_status": "verified",
            "derivation": None,
        } for i, e in enumerate(events)]

        report_html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>Sample bundle</title></head><body>"
            "<h1>Oathon sample bundle — refund-agent</h1>"
            "<p>Signed authority + chained actions: this bundle carries a "
            "signed mandate (refund limit 20,000 minor units, human approval "
            "above 10,000) and the hash-chained evidence of three operations. "
            "Run <code>oathon verify-bundle</code> on this directory to "
            "verify integrity and print the authority findings. Full report "
            "generation is part of the commercial product; this page is a "
            "placeholder so the bundle is structurally complete.</p>"
            "</body></html>")

        for stale in OUT.iterdir():
            if stale.name not in ("generate.py", "README.md"):
                shutil.rmtree(stale) if stale.is_dir() else stale.unlink()
        write_bundle(
            OUT,
            bundle_id=f"B-{ids.uuid7()}", report_id=f"SAMPLE-{ids.uuid7()}",
            created_at=ts(60),
            mandates=[mandate], revocations=[],
            key_records=[{"record_type": "genesis", "record": genesis}],
            writer_auths=[auth], events=events, segment_closes=[close],
            anchors=[], assertions=assertions, report_html=report_html)

    with zipfile.ZipFile(OUT / "sample-bundle.zip", "w",
                         zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(OUT.rglob("*")):
            if path.is_file() and path.name not in (
                    "generate.py", "README.md", "sample-bundle.zip"):
                zf.write(path, path.relative_to(OUT))
    print(f"sample bundle written to {OUT} (+ sample-bundle.zip)")


if __name__ == "__main__":
    sys.exit(main())
