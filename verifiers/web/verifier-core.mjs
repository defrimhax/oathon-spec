// Oathon v0.1 browser/Node verification core.
//
// Implemented ONLY from the public specification (CRYPTOGRAPHY.md, SPEC.md,
// INVARIANTS.md, spec/bundle-format-v0.1.md) and the normative vectors.
// The Python reference SDK was not consulted. No dependencies; Ed25519 and
// SHA-256 via WebCrypto (browser + Node >= 20). Zero network I/O.
//
// RFC 8785 note: canonical JSON serialization of parsed JSON equals
// JSON.stringify with object keys sorted by UTF-16 code units — ECMAScript
// number- and string-serialization IS the JCS algorithm (the RFC defines it
// in terms of ECMAScript). Protocol inputs reject non-finite numbers and
// stay in the safe integer domain (CRYPTO §2), so parse→serialize is exact.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

export const DOMAINS = {
  mandate: "WARRANT-MANDATE-SIGN-V0.1\u0000",
  revocation: "WARRANT-REVOCATION-SIGN-V0.1\u0000",
  "key-transition": "WARRANT-KEY-TRANSITION-SIGN-V0.1\u0000",
  "key-genesis": "WARRANT-KEY-GENESIS-SIGN-V0.1\u0000",
  "writer-authorization": "WARRANT-WRITER-AUTH-SIGN-V0.1\u0000",
  "segment-close": "WARRANT-SEGMENT-SIGN-V0.1\u0000",
};
const D_EVENT = "WARRANT-EVENT-HASH-V0.1\u0000";
const D_JSON = "WARRANT-DIGEST-JSON-V0.1\u0000";
const D_BYTES = "WARRANT-DIGEST-BYTES-V0.1\u0000";
const D_ANCHOR = "WARRANT-ANCHOR-INPUT-V0.1\u0000";

export function b64uEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function b64uDecode(text) {
  if (text.includes("=")) throw new Error("base64url must not be padded");
  const b64 = text.replaceAll("-", "+").replaceAll("_", "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// CRYPTO-003: RFC 8785 canonicalization of a parsed JSON value.
export function canonicalize(value) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === "object") {
      const out = {};
      for (const k of Object.keys(v).sort()) out[k] = sort(v[k]);
      return out;
    }
    if (typeof v === "number" && !Number.isFinite(v)) {
      throw new Error("non-finite number rejected (CRYPTO §2)");
    }
    return v;
  };
  return te.encode(JSON.stringify(sort(value)));
}

function concat(domain, bytes) {
  const d = te.encode(domain);
  const out = new Uint8Array(d.length + bytes.length);
  out.set(d); out.set(bytes, d.length);
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

export async function digestString(bytes) {
  return "sha256:" + b64uEncode(await sha256(bytes));
}

export async function digestJson(value) {           // CRYPTO §11
  return digestString(concat(D_JSON, canonicalize(value)));
}
export async function digestBytes(bytes) {          // CRYPTO §12
  return digestString(concat(D_BYTES, bytes));
}
export async function keyId(rawPub) {               // CRYPTO §4
  return "ed25519:" + b64uEncode(await sha256(rawPub));
}

// CRYPTO §6: deep copy, remove only signature.value, canonicalize, prefix.
export function signingBytes(obj, domain) {
  const copy = JSON.parse(JSON.stringify(obj));
  if (!copy.signature) throw new Error("object has no signature");
  delete copy.signature.value;
  return concat(domain, canonicalize(copy));
}

export async function verifySigned(obj, type, rawPub) {
  const domain = DOMAINS[type];
  if (!domain) throw new Error(`unknown signed-object type ${type}`);
  const sig = obj.signature || {};
  if (sig.alg !== "Ed25519") throw new Error("unsupported alg");
  if (sig.key_id !== (await keyId(rawPub))) {
    throw new Error("key_id mismatch (CRYPTO §4)");
  }
  const key = await subtle.importKey("raw", rawPub, { name: "Ed25519" }, false, ["verify"]);
  const ok = await subtle.verify("Ed25519", key, b64uDecode(sig.value),
    signingBytes(obj, domain));
  if (!ok) throw new Error("signature verification failed");
}

// CRYPTO §10: hash the event WITHOUT event_hash; prev_hash stays in.
export async function eventHash(event) {
  const copy = JSON.parse(JSON.stringify(event));
  delete copy.event_hash;
  if (!("prev_hash" in copy)) throw new Error("prev_hash must be present");
  return digestString(concat(D_EVENT, canonicalize(copy)));
}

// INV-003/004/005/007 over an ordered list of events.
export async function verifyChain(events) {
  if (!events.length) throw new Error("empty chain");
  let prev = null;
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if ((await eventHash(e)) !== e.event_hash) {
      throw new Error(`event ${i} (${e.event_id}): hash mismatch (INV-007)`);
    }
    if (prev === null) {
      if (e.sequence === 0 && e.prev_hash !== null) {
        throw new Error("genesis event must have prev_hash null (INV-003)");
      }
    } else {
      if (e.segment_id !== prev.segment_id || e.writer_id !== prev.writer_id) {
        throw new Error(`event ${i}: segment/writer changes mid-chain (INV-005)`);
      }
      if (e.sequence !== prev.sequence + 1) {
        throw new Error(`event ${i}: sequence not +1 (INV-004)`);
      }
      if (e.prev_hash !== prev.event_hash) {
        throw new Error(`event ${i} (${e.event_id}): prev_hash broken (INV-003)`);
      }
    }
    prev = e;
  }
}

export async function anchorInputDigest(close) {    // CRYPTO §14
  return digestString(concat(D_ANCHOR, canonicalize(close)));
}

// INV-006 as amended + CRYPTO §9b/§13.
export async function verifySegmentClose(close, auth, events, orgKeys) {
  const orgPub = orgKeys.get(auth.signature?.key_id);
  if (!orgPub) throw new Error("authorization signer key unknown");
  await verifySigned(auth, "writer-authorization", orgPub);
  const writerPub = b64uDecode(auth.writer_public_key);
  if ((await keyId(writerPub)) !== auth.writer_key_id) {
    throw new Error("writer_key_id does not match writer_public_key");
  }
  if (close.signature?.key_id !== auth.writer_key_id) {
    throw new Error("close not signed by the authorized writer key");
  }
  for (const f of ["org_id", "agent_id", "writer_id"]) {
    if (close[f] !== auth[f]) throw new Error(`authorization ${f} does not cover this segment`);
  }
  const at = close.signature.signed_at;
  if (at < auth.not_before || at > auth.not_after) {
    throw new Error("close signed outside the authorization window");
  }
  await verifySigned(close, "segment-close", writerPub);
  await verifyChain(events);
  const first = events[0], last = events[events.length - 1];
  if (close.first_event_hash !== first.event_hash ||
      close.last_event_hash !== last.event_hash) {
    throw new Error("close head hashes do not match chain");
  }
  if (close.event_count !== events.length) throw new Error("event_count mismatch");
  if (close.first_sequence !== first.sequence ||
      close.last_sequence !== last.sequence) {
    throw new Error("close sequences do not match chain");
  }
  for (const e of events) {
    if (e.segment_id !== close.segment_id) {
      throw new Error("chain event belongs to a different segment");
    }
  }
}

// SEGMENT-010 / INV-023.
export async function verifySegmentSequence(closes) {
  if (!closes.length) throw new Error("empty segment-close chain");
  let prevDigest = null;
  for (let i = 0; i < closes.length; i++) {
    const c = closes[i];
    if (c.segment_sequence !== i) {
      throw new Error(`close ${i}: segment_sequence not contiguous from 0`);
    }
    if (i === 0) {
      if (c.prev_segment_close_hash !== null) {
        throw new Error("first segment must have prev_segment_close_hash null");
      }
    } else if (c.prev_segment_close_hash !== prevDigest) {
      throw new Error(`close ${i}: prev_segment_close_hash mismatch (INV-023)`);
    }
    prevDigest = await anchorInputDigest(c);
  }
}

// spec/bundle-format-v0.1.md: key-history walk (step 2).
export async function buildKeyring(records) {
  const keys = new Map();
  const breaks = [];
  for (let i = 0; i < records.length; i++) {
    const { record_type, record } = records[i];
    if (i === 0) {
      if (record_type !== "genesis") throw new Error("history must start with genesis");
      const pub = b64uDecode(record.public_key);
      if ((await keyId(pub)) !== record.key_id) throw new Error("genesis key_id mismatch");
      await verifySigned(record, "key-genesis", pub);   // self-signed (§9a)
      keys.set(record.key_id, pub);
      continue;
    }
    if (record_type !== "transition") throw new Error("only one genesis allowed");
    const newPub = b64uDecode(record.new_public_key);
    if ((await keyId(newPub)) !== record.new_key_id) throw new Error("transition new_key_id mismatch");
    if (record.continuity === "administrative-recovery") {
      await verifySigned(record, "key-transition", newPub);
      breaks.push(record.transition_id);
    } else {
      const oldPub = keys.get(record.old_key_id);
      if (!oldPub) throw new Error("transition old key unknown");
      if (record.signature?.key_id !== record.old_key_id) {
        throw new Error("normal rotation must be signed by the old key");
      }
      await verifySigned(record, "key-transition", oldPub);
    }
    keys.set(record.new_key_id, newPub);
  }
  return { keys, breaks };
}

// spec/bundle-format-v0.1.md full verification.
// files: Map<relativePath, Uint8Array>. Returns [{artifact, status, detail}].
export async function verifyBundle(files) {
  const results = [];
  const ok = (artifact, detail) => results.push({ artifact, status: "VERIFIED", detail });
  const bad = (artifact, detail) => results.push({ artifact, status: "FAILED", detail });
  const dec = new TextDecoder();
  const readJson = (name) => JSON.parse(dec.decode(files.get(name)));

  let manifest;
  try {
    manifest = readJson("manifest.json");
  } catch {
    bad("manifest.json", "missing or unparseable");
    return results;
  }
  for (const [rel, expected] of Object.entries(manifest.artifacts || {})) {
    const bytes = files.get(rel);
    if (!bytes) { bad(rel, "listed in manifest but missing from bundle"); continue; }
    const got = await digestBytes(bytes);
    if (got === expected) ok(rel, "manifest digest matches file bytes");
    else bad(rel, `manifest digest mismatch (expected ${expected.slice(0, 24)}…)`);
  }
  if (results.some((r) => r.status === "FAILED")) return results;

  let keyring;
  try {
    keyring = await buildKeyring(readJson("key_records.json"));
    ok("key_records.json",
      `key history verified (${keyring.keys.size} key(s)` +
      (keyring.breaks.length ? `, ${keyring.breaks.length} DISCLOSED continuity break(s)` : "") + ")");
  } catch (e) {
    bad("key_records.json", String(e.message || e));
    return results;
  }

  for (const [file, type, idField] of [
    ["mandates.json", "mandate", "mandate_id"],
    ["revocations.json", "revocation", "revocation_id"],
    ["writer_auths.json", "writer-authorization", "authorization_id"],
  ]) {
    for (const obj of readJson(file)) {
      const label = `${file} · ${obj[idField]}`;
      try {
        const pub = keyring.keys.get(obj.signature?.key_id);
        if (!pub) throw new Error("signer key not in org key history");
        await verifySigned(obj, type, pub);
        ok(label, "signature verified against org key history");
      } catch (e) { bad(label, String(e.message || e)); }
    }
  }

  const events = dec.decode(files.get("events.jsonl")).split("\n")
    .filter(Boolean).map((l) => JSON.parse(l));
  const bySegment = new Map();
  for (const e of events) {
    if (!bySegment.has(e.segment_id)) bySegment.set(e.segment_id, []);
    bySegment.get(e.segment_id).push(e);
  }
  for (const [seg, list] of bySegment) {
    list.sort((a, b) => a.sequence - b.sequence);
    try {
      await verifyChain(list);
      ok(`segment ${seg}`, `${list.length} event(s), hashes and links verified`);
    } catch (e) { bad(`segment ${seg}`, String(e.message || e)); }
  }

  const closes = readJson("segment_closes.json");
  const auths = readJson("writer_auths.json");
  for (const close of closes) {
    const label = `segment-close ${close.segment_id}`;
    const auth = auths.find((a) => a.writer_id === close.writer_id &&
      a.writer_key_id === close.signature?.key_id);
    const segEvents = bySegment.get(close.segment_id) || [];
    if (!auth) { bad(label, "no covering writer authorization"); continue; }
    if (!segEvents.length) { bad(label, "close for a segment with no events in bundle"); continue; }
    try {
      await verifySegmentClose(close, auth, segEvents, keyring.keys);
      ok(label, "writer-key signature, authorization and chain consistency verified");
    } catch (e) { bad(label, String(e.message || e)); }
  }

  const byWriter = new Map();
  for (const c of closes) {
    if (!byWriter.has(c.writer_id)) byWriter.set(c.writer_id, []);
    byWriter.get(c.writer_id).push(c);
  }
  for (const [writer, list] of byWriter) {
    list.sort((a, b) => a.segment_sequence - b.segment_sequence);
    const contiguous = list[0].segment_sequence === 0 &&
      list.every((c, i) => c.segment_sequence === i);
    if (!contiguous) {
      bad(`writer ${writer}`, "segment-close run not contiguous from 0 — partial history DISCLOSED");
      continue;
    }
    try {
      await verifySegmentSequence(list);
      ok(`writer ${writer}`, `${list.length} segment close(s) chained (INV-023)`);
    } catch (e) { bad(`writer ${writer}`, String(e.message || e)); }
  }

  const anchors = readJson("anchors.json");
  const anchored = new Set(anchors.map((a) => a.segment_id));
  const unanchored = closes.filter((c) => !anchored.has(c.segment_id)).length;
  ok("anchors.json",
    `${anchors.length} receipt(s) present; ${unanchored} segment(s) unanchored ` +
    "(DISCLOSED). RFC 3161 token verification: NOT COVERED in this verifier.");

  const known = new Set();
  for (const e of events) known.add(e.event_id);
  for (const m of readJson("mandates.json")) known.add(m.mandate_id);
  for (const c of closes) known.add(c.segment_id);
  for (const r of readJson("revocations.json")) known.add(r.revocation_id);
  for (const a of auths) known.add(a.authorization_id);
  let unresolved = 0;
  const assertions = readJson("assertions.json");
  for (const a of assertions) {
    for (const ref of a.source_refs || []) {
      if (ref.startsWith("derived:")) continue;
      if (!known.has(ref.split("/").pop())) unresolved++;
    }
  }
  if (unresolved === 0) {
    ok("assertions.json", `${assertions.length} assertion(s); every source_ref resolves (INV-020)`);
  } else {
    bad("assertions.json", `${unresolved} unresolved source_ref(s)`);
  }
  return results;
}
