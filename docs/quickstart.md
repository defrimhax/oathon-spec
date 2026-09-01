# Oathon quickstart (≤30 minutes, no cloud account needed)

Everything below runs locally from a checkout of this repository, starting
at the repository root (DX-003). The Python snippets form **one Python
session** — run them in the same interpreter (or paste them into one file).
The scripted equivalent is `scripts/quickstart_audit.py`, which executes
exactly the commands below and is run in CI-style audits (DX-002).

**Prerequisite:** Python 3.12 or newer as `python3` (check with `python3 --version`).

## 1. Install

```bash
python3 -m venv .venv && .venv/bin/pip install -e packages/sdk-python
```

(Once the package is on PyPI, `pip install oathon-sdk` works anywhere; this
quickstart sticks to the checkout so it needs nothing but this repo.)

## 2. Generate your organization signing key (client-side, KEY-002)

```python
import json
from oathon import crypto, ids, keytools

org_priv, org_pub, org_key_id = keytools.generate_signing_key()
```

The private key never leaves your machine (KEY-003/INV-011). Store the seed
safely; loss without a backup key means administrative recovery with a
recorded continuity break (KEY-006).

## 3. Create and sign a mandate

A mandate declares who authorized which agent to do what, within which
limits. This one permits refunds up to 20 000 EUR minor units:

```python
ts = ids.protocol_timestamp()
mandate = crypto.sign_object({
    "mandate_id": ids.uuid7(), "spec_version": "0.1",
    "organization": {"org_id": "org_quickstart"},
    "principal": {"subject_id": "subj_me", "role": "Founder"},
    "agent": {"agent_id": "my-agent", "description": "quickstart agent",
              "environment": "dev"},
    "authority": {
        "permitted_actions": [{"action": "issue_refund",
                               "evaluable_fields": ["/amount/minor_units"]}],
        "forbidden_actions": [],
        "constraints": [{"action": "issue_refund",
                         "path": "/amount/minor_units", "op": "lte",
                         "value": 20000}],
        "approval_triggers": []},
    "oversight": {},
    "validity": {"not_before": "2026-01-01T00:00:00.000Z",
                 "not_after": "2027-01-01T00:00:00.000Z"},
    "signature": {"alg": "Ed25519", "key_id": org_key_id, "signed_at": ts},
}, crypto.DOMAIN_MANDATE, org_priv)

with open("mandate.json", "w") as f:
    json.dump(mandate, f)
with open("keys.json", "w") as f:
    json.dump({org_key_id: crypto.b64u_encode(org_pub)}, f)
```

(`keys.json` maps key ids to base64url public keys — the format
`oathon verify --keys` expects.)

Check it (the CLI lives in the venv you created in step 1):

```bash
.venv/bin/oathon validate mandate.json
.venv/bin/oathon verify mandate.json --type mandate --keys keys.json --at 2026-06-01T00:00:00.000Z
```

## 4. Record your first evidence — fully offline

```python
from oathon.spool import EvidenceWriter

writer = EvidenceWriter("./spool", "org_quickstart", "my-agent")
writer.append(writer.build_action_event(
    event_type="action_requested", mandate=mandate, action="issue_refund",
    params={"amount": {"minor_units": 4200, "currency": "EUR"}},
    operation_id=ids.uuid7()))
close = writer.close_segment()
```

Raw parameters are digested; only the mandate's declared `evaluable_fields`
are stored (EVENT-004/009). The append returns only after fsync (ADR-006).

## 5. Verify — including the segment-closure signature

Issue a writer authorization with your org key (still the same Python
session), then verify the whole spool:

```python
auth = keytools.build_writer_authorization(
    org_private_key=org_priv, org_id="org_quickstart", agent_id="my-agent",
    writer_id=writer.writer_id, writer_public_key=writer.writer_public_key,
    not_before="2026-01-01T00:00:00.000Z", not_after="2027-01-01T00:00:00.000Z")
with open("writer-auth.json", "w") as f:
    json.dump(auth, f)
with open("keys.json", "w") as f:
    json.dump({org_key_id: crypto.b64u_encode(org_pub),
               writer.writer_key_id: crypto.b64u_encode(writer.writer_public_key)}, f)
```

```bash
.venv/bin/oathon verify ./spool --spool --keys keys.json --writer-auth writer-auth.json
```

You should see `SPOOL OK: 1 closed segment(s) (1 events)` with closure
signatures verified. That evidence is now independently verifiable by
anyone you hand the spool, the authorization and the public keys to — no
server, no account.

## Beyond the quickstart

Server sync, Evidence Packs and Incident Reconstructions are part of the
commercial product (private repository). Any report's evidence bundle
verifies offline here with `oathon verify-bundle <dir>` — or in the
browser: `verifiers/web/index.html`.
