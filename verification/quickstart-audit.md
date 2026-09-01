# Quickstart friction audit (DX-001/DX-002)

Date: 2026-08-31. Method: `scripts/quickstart_audit.py` executes ONLY the
commands `docs/quickstart.md` states, in order, from a fresh clone —
```bash blocks in a hermetic shell (audit venv + the invoking python3 +
system paths), ```python blocks cumulatively as the single Python session
the document declares. Every run below actually executed; outputs are
verbatim.

## Run 1 — document as originally ported (verbatim result)

```
step  1 [bash  ]  2.3s FAIL python3 -m venv .venv && .venv/bin/pip install dist/oathon_s
step  2 [python]  0.0s FAIL from oathon import crypto, ids, keytools
step  3 [python]  0.0s FAIL mandate = crypto.sign_object(mandate_obj, ...)
step  4 [bash  ]  0.2s FAIL oathon validate mandate.json
step  5 [python]  0.0s FAIL from oathon.spool import EvidenceWriter
step  6 [bash  ]  0.1s OK   oathon verify ./spool --spool        ← masked, see F5/F7
TOTAL: 2.6s — FRICTION FOUND
```

## Friction findings, ranked

| # | Severity | Finding | Fix |
|---|---|---|---|
| F0 | Blocker | The public repository had **no quickstart at all** — external developers only had README fragments. | Ported and fixed docs/quickstart.md (this audit's subject). |
| F1 | Blocker | Step 1 installed from `dist/oathon_sdk-*.whl`, which does not exist in a checkout (dist/ is not shipped). Everything downstream cascaded. | Install `-e packages/sdk-python` from the checkout; PyPI path noted for later. |
| F2 | Blocker | Step 3 referenced an undefined `mandate_obj` ("build the object per the schema") — not literally executable, and `mandate.json`/`keys.json` used by the CLI check were never written by any step. | Full runnable mandate snippet incl. writing both files; `keys.json` format documented inline. |
| F3 | Medium | Bare `oathon` assumed an activated venv the doc never activated. | All CLI invocations use `.venv/bin/oathon`. |
| F4 | Medium | Python snippets silently assumed one continuous session (`org_priv`, `mandate`, `writer` carried across blocks). | Stated explicitly up front; the audit runner models it cumulatively. |
| F5 | Medium (audit tooling) | Run 1's runner leaked the repository's own development venv into PATH, making step 6 "pass" against an empty spool — a masked failure in the audit itself. | Runner made hermetic; recorded here rather than hidden. |
| F6 | Medium | `python3` ambiguity: on macOS the hermetic PATH resolved `/usr/bin/python3` (system 3.9), and `requires-python >=3.12` refused the install (run 2 failed on this). A real prerequisite the doc never stated. | Prerequisite line added ("Python 3.12 or newer as `python3`"); runner uses the invoking interpreter's bin dir, modeling the user's actual `python3`. |
| F7 | Low (product, PROPOSAL — not implemented) | `oathon verify <dir> --spool` on a nonexistent/empty spool reports `SPOOL OK: 0 closed segment(s)`. Verifying nothing should arguably be an error or explicit warning. Product change beyond doc scope → proposed for the SDK backlog, not changed in this pass. |
| F8 | Low | Step 5's closure-signature verification ("issue a writer authorization … pass --keys/--writer-auth") was prose without commands. | Full runnable snippet + exact CLI line; expected output stated. |

## Final run — fixed document, fresh clone, literal execution (verbatim)

```
step  1 [bash  ]     3.6s OK   python3 -m venv .venv && .venv/bin/pip install -e packages/s
step  2 [python]     0.6s OK   import json
step  3 [python]     0.1s OK   ts = ids.protocol_timestamp()
step  4 [bash  ]     0.4s OK   .venv/bin/oathon validate mandate.json
step  5 [python]     0.1s OK   from oathon.spool import EvidenceWriter
step  6 [python]     0.1s OK   auth = keytools.build_writer_authorization(
step  7 [bash  ]     0.1s OK   .venv/bin/oathon verify ./spool --spool --keys keys.json --w

TOTAL: 4.9s (0.1 min; DX-001 budget 30 min) — ALL STEPS PASSED
```

**DX-001 verdict: 4.9 seconds of execution against a 30-minute budget**, no
undocumented manual steps remaining. Honest caveat (standing since Phase 8):
the scripted run proves the documented path is complete and fast on a
machine with Python ≥3.12 and network for pip; no independent human
unfamiliar with Oathon has timed a manual walkthrough yet — that remains
the strongest possible evidence and requires a human.
