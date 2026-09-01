# Sample: refund-agent

Signed authority + chained actions, in one committed bundle: a mandate that
permits refunds up to 20,000 minor units with human approval required above
10,000, and the hash-chained evidence of three operations — one clean flow,
one 75,000 refund executed with no approval, one refund executed after the
approval was **denied**.

Verify it and print the findings (from the repository root):

```bash
oathon verify-bundle samples/refund-agent/
```

`sample-bundle.zip` is the same bundle for drag-and-drop into the browser
verifier (`verifiers/web/index.html`). All keys are INSECURE deterministic
demo keys; all data is synthetic. `generate.py` regenerates the bundle
(new ids each run) using only the public SDK.
