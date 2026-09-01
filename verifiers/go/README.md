# Go verifier

**Built without reference to the Python SDK — implemented from the
specification alone; see the conformance table** ([CONFORMANCE.md](CONFORMANCE.md)). This verifier was written from
`CRYPTOGRAPHY.md`, `SPEC.md`, `INVARIANTS.md`, `SECURITY.md` and the
normative vectors under `spec/vectors/v0.1/` **only** — the Python
reference SDK was not consulted during its implementation.

Scope: offline verification — signed objects (mandates, revocations, key
genesis/transitions, writer authorizations, segment closes), event hashes
and chains, per-writer segment-close chains, the digest helpers, and the
RFC 3161 anchor-input digest. Not covered (out of scope here): RFC 3161
token (DER/CMS) parsing, networking, and report generation.

```bash
cd verifiers/go
go run . -vectors ../../spec/vectors/v0.1
```

Exit code 0 requires every vector case to match its expected outcome —
including the mutation/negative cases, which must be REJECTED.

Dependency: `github.com/gowebpki/jcs` (RFC 8785 canonicalization, the
algorithm the spec references); everything else is the Go standard library.
