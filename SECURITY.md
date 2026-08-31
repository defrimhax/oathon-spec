# Oathon — Security Model

## 1. Security objective

Oathon provides cryptographically verifiable records describing:

- authority declared by a customer
- evidence recorded by Oathon instrumentation
- integrity of that evidence after durable recording
- integrity of signed segment closures
- external timestamp receipts where available

Oathon does not prove that a customer, agent, operating system, or application told the truth before evidence was created.

## 2. Trust boundaries

- **Customer application** — Trusted to provide the event semantics it records. Potentially compromised or dishonest.
- **Oathon SDK** — Responsible for canonicalization, hashing, local persistence, chaining, signing support, and synchronization.
- **Customer signing key** — Highest-value customer-side secret. The Oathon server MUST NOT possess it. It SHOULD live only where mandates, revocations, key transitions, and writer authorizations are signed (e.g. an admin workstation) — not in agent runtimes.
- **Writer signing keys** — Per-writer keys certified by the organization key (CRYPTOGRAPHY.md §9b). Present in agent runtimes; lower-value than the org key. Compromise of a writer key affects that writer's segment closures within its authorization window, not mandates or key history.
- **Oathon API/database** — Assumed potentially breachable. A database leak SHOULD expose primarily digests, identifiers, signatures, and limited metadata.
- **Timestamping authority** — Trusted only for the guarantees provided by the selected RFC 3161 TSA and its certificate policy.
- **Report consumer** — MAY independently verify bundles without trusting the visual PDF alone.

## 3. Threat actors

The design MUST consider: external attacker, malicious tenant, compromised Oathon API, compromised customer application, dishonest customer, leaked API credential, leaked customer signing key, malicious/buggy future developer, accidental operator error.

## 4. Guarantees

- **SEC-001** — Valid signatures MUST be independently verifiable using retained historical public keys.
- **SEC-002** — Historical event mutation MUST be detectable when the corresponding chain artifacts remain available.
- **SEC-003** — Cross-tenant database queries MUST include tenant scoping through a repository/data-access abstraction that makes unscoped access difficult.
- **SEC-004** — Cross-tenant isolation MUST be tested using adversarial integration tests against real Postgres.
- **SEC-005** — API keys MUST contain at least 256 bits of cryptographically secure random secret material. Only a one-way digest of API-key secret material MUST be stored.
- **SEC-006** — Secret comparison MUST use constant-time comparison where applicable.
- **SEC-007** — Application logs MUST NOT contain: API-key secrets, private keys, raw customer payloads, raw prompts, raw model outputs.
- **SEC-008** — Server evidence rows MUST be append-only at the application layer. Database privileges SHOULD further prevent normal application code from updating evidence rows.
- **SEC-009** — Deletion due to retention MUST be represented in retention metadata so reports can distinguish expected retention expiry from unexplained gaps where possible.
- **SEC-010** — Dependency versions MUST be locked reproducibly. Crypto-related dependencies MUST undergo explicit review before introduction. Popularity alone MUST NOT be treated as a security proof.
- **SEC-011** — CI MUST run dependency vulnerability auditing.
- **SEC-012** — No compliance certification, legal admissibility, insurance acceptance, or regulatory approval MUST be claimed unless independently established.

## 5. Non-guarantees

Oathon v0.1 does NOT guarantee:

- truthfulness of events before recording
- uncompromised customer runtime
- prevention of unauthorized agent actions
- legal admissibility
- non-repudiation in every jurisdiction
- public non-equivocation from RFC 3161 alone
- survival if customer and Oathon both delete all copies of evidence and receipts
- perfect event completeness when using best-effort telemetry capture
- validity of legal/insurance conclusions

## 6. Key compromise

A compromised signing key can create apparently valid future signatures until its compromise is recognized. Key revocation MUST NOT rewrite historical facts. Reports MUST disclose relevant key-continuity events. Administrative recovery without a valid predecessor signature creates a cryptographic continuity break and MUST be labeled as such.

## 7. Server compromise

A compromised Oathon server without customer private keys SHOULD NOT be able to create valid customer signatures.

It MAY be capable of: deleting records, suppressing reports, withholding anchors, serving misleading UI, delaying ingestion.

Therefore evidence bundles MUST be independently verifiable.

## 8. Customer dishonesty before recording

A customer controlling the signing runtime can fabricate an event and sign it. Oathon proves integrity after recording under stated conditions. It does not prove physical or business-world truth.

## 9. RFC 3161 limitation

An RFC 3161 receipt establishes a timestamp assertion about a specific message imprint. It does not itself act as a globally visible append-only transparency log. This distinction MUST appear in technical documentation and cryptographic appendices.

## 10. Raw data policy

Raw payload storage is OUT OF SCOPE for v0.1.

Adding it requires: human approval, threat-model revision, privacy design, encryption/key lifecycle design, retention analysis, new requirements and tests.
