// Run the browser verification core against the normative vectors under
// Node (same module the page uses). Output format matches the Go verifier
// so scripts/conformance.py can build the cross-implementation table.
//
// Usage: node conformance.mjs [vector-dir]
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey } from "node:crypto";
import {
  anchorInputDigest, b64uEncode, canonicalize, digestJson, digestBytes,
  eventHash, signingBytes, verifyChain, verifySegmentClose,
  verifySegmentSequence, verifySigned,
} from "./verifier-core.mjs";

const dir = process.argv[2] ?? "../../spec/vectors/v0.1";
const vectors = JSON.parse(readFileSync(`${dir}/vectors.json`, "utf8"));
const keysDoc = JSON.parse(readFileSync(`${dir}/keys.json`, "utf8"));

// Derive raw public keys from the vector seeds (keys.json contract) using
// node:crypto only for the seed->public derivation.
const keys = new Map();
for (const entry of Object.values(keysDoc.keys)) {
  const seed = Buffer.from(entry.seed_hex, "hex");
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const pub = createPublicKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" }))
    .export({ format: "der", type: "spki" });
  const raw = new Uint8Array(pub.subarray(pub.length - 32));
  if (b64uEncode(raw) !== entry.public_key_b64u) {
    throw new Error(`keys.json inconsistent for ${entry.key_id}`);
  }
  keys.set(entry.key_id, raw);
}

async function expectVerdict(fn, expected) {
  let verified = true, err = null;
  try { await fn(); } catch (e) { verified = false; err = e; }
  if (verified !== expected) {
    throw new Error(`verified=${verified} want ${expected} (${err?.message ?? ""})`);
  }
}

async function runCase(c) {
  const exp = c.expected;
  switch (c.kind) {
    case "sign-verify": {
      await expectVerdict(
        () => verifySigned(c.object, c.type, keys.get(c.verify_key)), exp.verified);
      if (exp.verified && exp.canonical_signing_object_b64u) {
        const canonical = signingBytes(c.object, "");
        if (b64uEncode(canonical) !== exp.canonical_signing_object_b64u) {
          throw new Error("canonical signing bytes differ");
        }
      }
      return;
    }
    case "event-hash": {
      if ((await eventHash(c.object)) !== exp.event_hash) {
        throw new Error("event_hash differs");
      }
      if (exp.canonical_b64u &&
          b64uEncode(canonicalize(c.object)) !== exp.canonical_b64u) {
        throw new Error("canonical bytes differ");
      }
      return;
    }
    case "chain":
      return expectVerdict(() => verifyChain(c.events), exp.verified);
    case "segment":
      return expectVerdict(
        () => verifySegmentClose(c.close, c.writer_auth, c.events, keys), exp.verified);
    case "segment-chain":
      return expectVerdict(() => verifySegmentSequence(c.closes), exp.verified);
    case "anchor": {
      if ((await anchorInputDigest(c.object)) !== exp.digest) {
        throw new Error("anchor input digest differs");
      }
      return;
    }
    case "digest-json": {
      if ((await digestJson(c.value)) !== exp.digest) throw new Error("digest_json differs");
      return;
    }
    case "digest-bytes": {
      const raw = Uint8Array.from(Buffer.from(c.value_hex, "hex"));
      if ((await digestBytes(raw)) !== exp.digest) throw new Error("digest_bytes differs");
      return;
    }
    default:
      throw new Error(`unknown kind ${c.kind}`);
  }
}

let failures = 0;
for (const c of vectors.cases) {
  try {
    await runCase(c);
    console.log(`${c.name}: PASS`);
  } catch (e) {
    console.log(`${c.name}: FAIL ${e.message}`);
    failures++;
  }
}
console.log(`TOTAL: ${vectors.cases.length - failures}/${vectors.cases.length}`);
process.exit(failures ? 1 : 0);
