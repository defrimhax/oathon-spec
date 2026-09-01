# oathon-sdk

Reference SDK and CLI for the **Oathon protocol**: organizations sign
immutable Mandates declaring what an autonomous AI agent may do; agent
runtimes record hash-chained, writer-signed evidence; anyone holding an
evidence bundle can verify it **offline** — no server, no account.

```bash
pip install oathon-sdk
oathon verify-bundle <bundle-directory>
```

The CLI also provides `oathon validate` (schemas + semantic rules) and
`oathon verify` (signatures, event chains, segment closures). The library
exposes the byte-exact primitives (RFC 8785 canonicalization, domain-
separated Ed25519 signing, event hashing, RFC 3161 anchor verification with
pinned TSA certificates) plus the crash-recoverable local evidence spool.

Protocol **v0.1 is frozen**; wire identifiers remain `WARRANT-*-V0.1` for
compatibility (the product's former name — see the protocol identifier note
in the specification). Full spec, JSON Schemas, and normative known-answer
vectors: <https://github.com/def933/oathon-spec>.

Oathon proves evidence integrity **after** durable recording under stated
conditions — see the specification's SECURITY.md for the honest list of
non-guarantees. Licensed Apache-2.0.
