"""Cross-implementation conformance table: Python (reference SDK) vs Go
(verifiers/go, implemented from the specification alone).

Usage: python scripts/conformance.py <name>=<output-file> [...]
where each file holds that implementation's per-case output lines
(e.g. go=/tmp/go.txt web=/tmp/web.txt).
Prints a markdown table and exits non-zero unless BOTH columns pass on
every case.
"""

import json
import sys
from pathlib import Path

from oathon import crypto
from oathon.crypto import VerificationError
from oathon.verify import (
    KeySet,
    verify_chain,
    verify_segment_close,
    verify_segment_sequence,
)

ROOT = Path(__file__).resolve().parent.parent
VDIR = ROOT / "spec" / "vectors" / "v0.1"


def python_result(case, keyset, raw_keys):
    kind = case["kind"]
    expected = case["expected"]
    try:
        if kind == "sign-verify":
            pub = raw_keys[case["verify_key"]]
            try:
                crypto.verify_object(case["object"],
                                     crypto.SIGN_DOMAINS[case["type"]], pub)
                verified = True
            except VerificationError:
                verified = False
            if verified != expected["verified"]:
                return False
            if verified and "canonical_signing_object_b64u" in expected:
                canonical = crypto.b64u_encode(crypto.signing_input(case["object"], b""))
                if canonical != expected["canonical_signing_object_b64u"]:
                    return False
            return True
        if kind == "event-hash":
            if crypto.event_hash(case["object"]) != expected["event_hash"]:
                return False
            if "canonical_b64u" in expected:
                return crypto.b64u_encode(
                    crypto.canonicalize(case["object"])) == expected["canonical_b64u"]
            return True
        if kind == "chain":
            try:
                verify_chain(case["events"])
                return expected["verified"] is True
            except VerificationError:
                return expected["verified"] is False
        if kind == "segment":
            try:
                verify_segment_close(case["close"], case["events"],
                                     case["writer_auth"], keyset)
                return expected["verified"] is True
            except VerificationError:
                return expected["verified"] is False
        if kind == "segment-chain":
            try:
                verify_segment_sequence(case["closes"])
                return expected["verified"] is True
            except VerificationError:
                return expected["verified"] is False
        if kind == "anchor":
            return crypto.anchor_input_digest(case["object"]) == expected["digest"]
        if kind == "digest-json":
            return crypto.digest_json(case["value"]) == expected["digest"]
        if kind == "digest-bytes":
            return crypto.digest_bytes(
                bytes.fromhex(case["value_hex"])) == expected["digest"]
    except Exception:  # noqa: BLE001 — any crash is a conformance failure
        return False
    return False


def main() -> int:
    vectors = json.loads((VDIR / "vectors.json").read_text())
    keys = json.loads((VDIR / "keys.json").read_text())
    keyset = KeySet.from_json(
        {e["key_id"]: e["public_key_b64u"] for e in keys["keys"].values()})
    raw_keys = {e["key_id"]: crypto.b64u_decode(e["public_key_b64u"])
                for e in keys["keys"].values()}

    impls = []
    for arg in sys.argv[1:]:
        label, _, path = arg.partition("=")
        status = {}
        for line in Path(path).read_text().splitlines():
            if ": " in line and not line.startswith("TOTAL"):
                name, verdict = line.split(": ", 1)
                status[name] = "PASS" if verdict.strip() == "PASS" else "FAIL"
        impls.append((label.capitalize(), status))

    rows, ok = [], True
    for case in vectors["cases"]:
        py = "PASS" if python_result(case, keyset, raw_keys) else "FAIL"
        cols = [py] + [s.get(case["name"], "MISSING") for _, s in impls]
        rows.append((case["name"], cols))
        ok = ok and all(c == "PASS" for c in cols)

    width = max(len(r[0]) for r in rows)
    headers = ["Python"] + [label for label, _ in impls]
    print(f"| {'vector id'.ljust(width)} | " + " | ".join(h.ljust(6) for h in headers) + " |")
    print(f"|{'-' * (width + 2)}|" + "|".join("-" * 8 for _ in headers) + "|")
    for name, cols in rows:
        print(f"| {name.ljust(width)} | " + " | ".join(c.ljust(6) for c in cols) + " |")
    totals = []
    for i, h in enumerate(headers):
        n = sum(1 for _, cols in rows if cols[i] == "PASS")
        totals.append(f"{h} {n}/{len(rows)}")
    print(f"\n{len(rows)} vectors; " + ", ".join(totals))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
