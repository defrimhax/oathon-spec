# Oathon protocol specification and SDK

[![CI](https://github.com/def933/oathon-spec/actions/workflows/ci.yml/badge.svg)](https://github.com/def933/oathon-spec/actions/workflows/ci.yml)
[![conformance](https://github.com/def933/oathon-spec/actions/workflows/conformance.yml/badge.svg)](https://github.com/def933/oathon-spec/actions/workflows/conformance.yml)

**Oathon is signed authority + chained actions.** An organization signs an
immutable Mandate declaring what an agent may do; the agent's runtime
records every action into hash-chained, writer-signed, optionally
RFC 3161-timestamped evidence; and any party holding an evidence bundle can
verify — offline, with no account and no server — that the evidence is
intact, what authority was declared, and whether recorded actions fell
within it. This repository
contains the complete protocol specification, JSON Schemas, normative test
vectors, and the reference Python SDK with its CLI. It is licensed
Apache-2.0.

## See an incident in one command

The repo ships a ready sample: a refund agent with a 20,000 limit and a
human-approval trigger — including one over-limit refund and one refund
executed after a denied approval.

```bash
pip install -e packages/sdk-python
oathon verify-bundle samples/refund-agent/
```

Integrity verifies, and the authority findings print both incidents with
their reasons (AUTH-003/AUTH-005). `samples/refund-agent/sample-bundle.zip`
drops straight into the browser verifier.

## Verify a bundle in 60 seconds

```bash
pip install oathon-sdk
oathon verify-bundle <bundle-directory>
```

This checks every artifact digest in the manifest, walks the organization's
key history, verifies mandate/revocation/authorization signatures, recomputes
every event hash and chain link, verifies segment closures and per-writer
segment chains, verifies RFC 3161 receipts against the bundled TSA
certificates, and confirms that every report assertion's references resolve.
Exit code 0 means the bundle is internally consistent; disclosed gaps
(unanchored segments, key-continuity breaks) are printed, never hidden.

Until the package is published on PyPI, install from a checkout instead:
`pip install -e packages/sdk-python`.

## Implement a compatible signer from this spec alone

[CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) defines every byte: RFC 8785 (JCS)
canonicalization, SHA-256, Ed25519, domain-separated signing inputs, event
hashing, and the RFC 3161 anchor input. [spec/](spec/) holds the JSON
Schemas and [spec/vectors/v0.1/](spec/vectors/v0.1/) the normative
known-answer vectors: deterministic test keys (with public derivation),
expected canonical bytes, expected hashes, exact expected Ed25519
signatures, and a real RFC 3161 receipt from a public TSA. A conforming
implementation MUST reproduce every expected value;
[spec/protocol-v0.1.md](spec/protocol-v0.1.md) is the implementer's guide.
The vector suite is also runnable here: `pytest` after installing the SDK.

This claim is demonstrated, not just asserted: [verifiers/go/](verifiers/go/)
holds a second verifier implemented from the specification alone (the Python
SDK was not consulted), passing all 21 vectors and rejecting every mutation
case — and [verifiers/web/](verifiers/web/) a third, in JavaScript, that
also powers a drag-and-drop **browser bundle verifier** (open
verifiers/web/index.html; your bundle never leaves the browser). See the
three-way table in [verifiers/go/CONFORMANCE.md](verifiers/go/CONFORMANCE.md).

## Trust model, honestly

Oathon proves the integrity of evidence **after** durable recording, under
the conditions stated in [SECURITY.md](SECURITY.md). It does not prove that
a customer-controlled runtime told the truth before recording, that the
runtime was uncompromised, or anything about legal admissibility — see
[SECURITY.md §5](SECURITY.md) for the full list of non-guarantees, which are
part of the design. An RFC 3161 receipt shows a digest existed by the TSA's
timestamp under that TSA's certificate policy; it is not a public
transparency log.

## Protocol version status

Protocol **v0.1 is frozen**. The domain-separation identifiers
(`WARRANT-*-V0.1` — retained for wire compatibility from the project's
former name; see the protocol identifier note in CRYPTOGRAPHY.md §5), the
schemas' field semantics, and the committed vectors will not change within
v0.1. Any semantic change requires a new spec version per **INV-022**
([INVARIANTS.md](INVARIANTS.md)); see [CONTRIBUTING.md](CONTRIBUTING.md).

## Repository layout

- [SPEC.md](SPEC.md) — protocol behavior (mandates, authority evaluation,
  events, segments, SDK, anchoring, bundles). Server behavior lives in the
  private repository.
- [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) · [INVARIANTS.md](INVARIANTS.md) ·
  [SECURITY.md](SECURITY.md) · [PROVENANCE.md](PROVENANCE.md)
- [spec/](spec/) — schemas, prose spec, examples, normative vectors
- [packages/sdk-python/](packages/sdk-python/) — reference SDK + `oathon` CLI
  (validate, verify, verify-bundle) and the full test suite
