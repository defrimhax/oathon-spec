# Contributing

- **Protocol changes**: v0.1 is frozen. Any change to cryptographic bytes,
  schema semantics, or committed vectors requires a **new protocol version**
  (INV-022 in [INVARIANTS.md](INVARIANTS.md)) — open an issue proposing it;
  do not send PRs that mutate v0.1 artifacts.
- **Issues and questions** are welcome: ambiguities found while implementing
  from the spec are treated as bugs in the spec.
- **Security reports**: read [SECURITY.md](SECURITY.md) for the threat model
  and stated non-guarantees first — a report that something outside the
  guarantees is "broken" is expected behavior. Genuine issues within the
  guarantees (e.g. a mutation the verification suite fails to detect) are
  high priority; please report them privately via a GitHub security
  advisory.
- **SDK fixes** (bugs, portability, docs) are welcome as PRs with tests.
  Tests are evidence: a failing test is never weakened to pass.
