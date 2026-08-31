"""Evidence bundles (BUNDLE-001..005): the independently verifiable
substrate behind every report. The PDF/HTML is a view; this is the trust
root (ADR-010).

Layout: manifest.json + mandates.json, revocations.json, key_records.json,
writer_auths.json, events.jsonl (canonical JCS lines), segment_closes.json,
anchors.json, tsa_certs/, assertions.json, report.html. The manifest lists
the digest_bytes of every artifact (BUNDLE-005). No raw customer payloads
exist anywhere in the pipeline, so none can be here (BUNDLE-003/INV-010).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from . import crypto
from .crypto import VerificationError
from .jsonutil import loads_strict
from .keyring import build_org_keyring
from .verify import KeySet, verify_chain, verify_segment_close, verify_segment_sequence, verify_signed


class BundleError(Exception):
    pass


def write_bundle(
    out_dir: str | Path,
    *,
    bundle_id: str,
    report_id: str,
    created_at: str,
    mandates: list[dict],
    revocations: list[dict],
    key_records: list[dict],
    writer_auths: list[dict],
    events: list[dict],
    segment_closes: list[dict],
    anchors: list[dict],
    assertions: list[dict],
    report_html: str,
    tsa_certs: dict[str, bytes] | None = None,
) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    files: dict[str, bytes] = {
        "mandates.json": json.dumps(mandates, ensure_ascii=False, indent=1).encode(),
        "revocations.json": json.dumps(revocations, ensure_ascii=False, indent=1).encode(),
        "key_records.json": json.dumps(key_records, ensure_ascii=False, indent=1).encode(),
        "writer_auths.json": json.dumps(writer_auths, ensure_ascii=False, indent=1).encode(),
        "events.jsonl": b"".join(crypto.canonicalize(e) + b"\n" for e in events),
        "segment_closes.json": json.dumps(segment_closes, ensure_ascii=False, indent=1).encode(),
        "anchors.json": json.dumps(anchors, ensure_ascii=False, indent=1).encode(),
        "assertions.json": json.dumps(assertions, ensure_ascii=False, indent=1).encode(),
        "report.html": report_html.encode(),
    }
    for name, pem in (tsa_certs or {}).items():
        files[f"tsa_certs/{name}"] = pem

    manifest = {
        "bundle_id": bundle_id,
        "report_id": report_id,
        "created_at": created_at,
        "spec_version": "0.1",
        "artifacts": {},
    }
    for rel, data in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        manifest["artifacts"][rel] = crypto.digest_bytes(data)
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1))
    return out


def verify_bundle(bundle_dir: str | Path) -> dict[str, Any]:
    """BUNDLE-004: full offline verification, no Oathon API involved.

    Hard failures (digest mismatch, signature failure, chain break) raise
    BundleError. Structural gaps that a report must disclose (unanchored
    segments, key continuity breaks, incomplete writer chains) are RETURNED
    in the summary — visible, never repaired (INV-014).
    """
    bundle = Path(bundle_dir)
    try:
        manifest = loads_strict((bundle / "manifest.json").read_bytes())
    except FileNotFoundError as exc:
        raise BundleError("manifest.json missing") from exc

    for rel, expected in manifest["artifacts"].items():
        try:
            data = (bundle / rel).read_bytes()
        except FileNotFoundError as exc:
            raise BundleError(f"artifact missing: {rel}") from exc
        actual = crypto.digest_bytes(data)
        if actual != expected:
            raise BundleError(f"artifact digest mismatch: {rel}")

    def load(rel):
        return loads_strict((bundle / rel).read_bytes())

    key_records = load("key_records.json")
    keyring = build_org_keyring(key_records)
    keyset: KeySet = keyring["keyset"]

    mandates = load("mandates.json")
    for mandate in mandates:
        verify_signed(mandate, "mandate", keyset)
    revocations = load("revocations.json")
    for revocation in revocations:
        verify_signed(revocation, "revocation", keyset)
    writer_auths = load("writer_auths.json")
    for auth in writer_auths:
        verify_signed(auth, "writer-authorization", keyset)

    events = [loads_strict(line) for line in
              (bundle / "events.jsonl").read_bytes().split(b"\n") if line]
    by_segment: dict[str, list[dict]] = {}
    for event in events:
        by_segment.setdefault(event["segment_id"], []).append(event)
    for seg_events in by_segment.values():
        seg_events.sort(key=lambda e: e["sequence"])
        verify_chain(seg_events)

    closes = load("segment_closes.json")
    auth_by_writer_key = {
        (a["writer_id"], a["writer_key_id"]): a for a in writer_auths
    }
    unmatched_closes = []
    for close in closes:
        auth = auth_by_writer_key.get((close["writer_id"], close["signature"]["key_id"]))
        seg_events = by_segment.get(close["segment_id"], [])
        if auth is None or not seg_events:
            unmatched_closes.append(close["segment_id"])
            continue
        ks = KeySet(dict(keyset.keys))
        ks.keys[auth["writer_key_id"]] = crypto.b64u_decode(auth["writer_public_key"])
        verify_segment_close(close, seg_events, auth, ks)

    # Per-writer close chains, where the bundle holds a contiguous run.
    partial_writer_chains = []
    by_writer: dict[str, list[dict]] = {}
    for close in closes:
        by_writer.setdefault(close["writer_id"], []).append(close)
    for writer_id, wcloses in by_writer.items():
        wcloses.sort(key=lambda c: c["segment_sequence"])
        seqs = [c["segment_sequence"] for c in wcloses]
        if seqs == list(range(seqs[0], seqs[-1] + 1)) and seqs[0] == 0:
            verify_segment_sequence(wcloses)
        else:
            partial_writer_chains.append(writer_id)

    anchors = load("anchors.json")
    anchored_segments = set()
    anchor_verified = 0
    tsa_dir = bundle / "tsa_certs"
    roots = sorted(tsa_dir.glob("*cacert*.pem")) if tsa_dir.exists() else []
    tsa_certs = sorted(tsa_dir.glob("*tsa*.pem")) if tsa_dir.exists() else []
    close_by_segment = {c["segment_id"]: c for c in closes}
    for entry in anchors:
        close = close_by_segment.get(entry["segment_id"])
        if close is None:
            raise BundleError(f"anchor for unknown segment {entry['segment_id']}")
        if roots and tsa_certs:
            from .anchor import verify_anchor_receipt

            verify_anchor_receipt(
                base64.b64decode(entry["receipt_b64"]), close,
                entry.get("nonce"), [r.read_bytes() for r in roots],
                tsa_certs[0].read_bytes(),
            )
            anchor_verified += 1
        anchored_segments.add(entry["segment_id"])

    # INV-020: every assertion's source refs must resolve inside the bundle.
    assertions = load("assertions.json")
    known_ids = ({e["event_id"] for e in events}
                 | {m["mandate_id"] for m in mandates}
                 | {c["segment_id"] for c in closes}
                 | {r["revocation_id"] for r in revocations}
                 | {a["authorization_id"] for a in writer_auths})
    for assertion in assertions:
        for ref in assertion.get("source_refs", []):
            ref_id = ref.split("/")[-1]
            if ref_id not in known_ids and not ref.startswith("derived:"):
                raise BundleError(
                    f"assertion {assertion.get('assertion_id')} references "
                    f"unknown artifact {ref}"
                )

    unanchored = sorted(
        c["segment_id"] for c in closes if c["segment_id"] not in anchored_segments
    )
    return {
        "bundle_id": manifest["bundle_id"],
        "artifacts_verified": len(manifest["artifacts"]),
        "events": len(events),
        "segments": len(by_segment),
        "closes_verified": len(closes) - len(unmatched_closes),
        "closes_unverified": unmatched_closes,
        "anchors_verified": anchor_verified,
        "unanchored_segments": unanchored,
        "key_continuity_breaks": keyring["continuity_breaks"],
        "partial_writer_chains": partial_writer_chains,
        "assertions": len(assertions),
    }
