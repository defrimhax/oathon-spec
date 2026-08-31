// Oathon v0.1 cross-implementation verifier (Go).
//
// Implemented ONLY from the public specification: CRYPTOGRAPHY.md, SPEC.md,
// INVARIANTS.md, SECURITY.md and the normative vectors under
// spec/vectors/v0.1/. The Python reference implementation was NOT consulted.
//
// Scope: offline verification — signed objects (mandates, revocations, key
// genesis/transition, writer authorizations, segment closes), event hashes
// and chains, per-writer segment-close chains, digest helpers, and the
// RFC 3161 anchor-input digest. No networking, no report generation, no
// RFC 3161 token parsing (receipt DER verification is NOT COVERED here; the
// anchor-input digest that a receipt's messageImprint must equal IS covered).
//
// Usage: go run . -vectors ../../spec/vectors/v0.1
// Prints one line per vector case ("<name>: PASS/FAIL") and exits non-zero
// on any mismatch with the expected outcome.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gowebpki/jcs"
)

// CRYPTOGRAPHY.md §5 — domain separation (trailing byte 0x00 is part of the
// domain; the wire identifiers remain WARRANT-*-V0.1 per the compatibility
// note).
var domains = map[string]string{
	"mandate":              "WARRANT-MANDATE-SIGN-V0.1\x00",
	"revocation":           "WARRANT-REVOCATION-SIGN-V0.1\x00",
	"key-transition":       "WARRANT-KEY-TRANSITION-SIGN-V0.1\x00",
	"key-genesis":          "WARRANT-KEY-GENESIS-SIGN-V0.1\x00",
	"writer-authorization": "WARRANT-WRITER-AUTH-SIGN-V0.1\x00",
	"segment-close":        "WARRANT-SEGMENT-SIGN-V0.1\x00",
}

const (
	domainEventHash   = "WARRANT-EVENT-HASH-V0.1\x00"
	domainDigestJSON  = "WARRANT-DIGEST-JSON-V0.1\x00"
	domainDigestBytes = "WARRANT-DIGEST-BYTES-V0.1\x00"
	domainAnchorInput = "WARRANT-ANCHOR-INPUT-V0.1\x00"
)

var b64u = base64.RawURLEncoding // CRYPTO-005: base64url, no padding

func digestString(sum [32]byte) string { // CRYPTO §3
	return "sha256:" + b64u.EncodeToString(sum[:])
}

func keyID(pub ed25519.PublicKey) string { // CRYPTO §4
	sum := sha256.Sum256(pub)
	return "ed25519:" + b64u.EncodeToString(sum[:])
}

func canonicalize(raw json.RawMessage) ([]byte, error) { // CRYPTO-003 (RFC 8785)
	return jcs.Transform(raw)
}

// signingInput implements CRYPTOGRAPHY.md §6: deep-copy the object, remove
// only signature.value, JCS-canonicalize, UTF-8 encode, prepend the domain.
// Raw JSON is manipulated as json.RawMessage maps so numbers are never
// round-tripped through floats.
func signingInput(objRaw json.RawMessage, domain string) ([]byte, []byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(objRaw, &top); err != nil {
		return nil, nil, err
	}
	sigRaw, ok := top["signature"]
	if !ok {
		return nil, nil, fmt.Errorf("object has no signature")
	}
	var sig map[string]json.RawMessage
	if err := json.Unmarshal(sigRaw, &sig); err != nil {
		return nil, nil, err
	}
	delete(sig, "value")
	newSig, err := json.Marshal(sig)
	if err != nil {
		return nil, nil, err
	}
	top["signature"] = newSig
	rebuilt, err := json.Marshal(top)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := canonicalize(rebuilt)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(domain), canonical...), canonical, nil
}

type signatureBlock struct {
	Alg      string `json:"alg"`
	KeyID    string `json:"key_id"`
	SignedAt string `json:"signed_at"`
	Value    string `json:"value"`
}

// verifySigned checks a signed object against a provided public key per
// CRYPTO §6, including the §4 rule that a key_id mismatch MUST fail.
func verifySigned(objRaw json.RawMessage, objType string, pub ed25519.PublicKey) error {
	domain, ok := domains[objType]
	if !ok {
		return fmt.Errorf("unknown signed-object type %q", objType)
	}
	var holder struct {
		Signature signatureBlock `json:"signature"`
	}
	if err := json.Unmarshal(objRaw, &holder); err != nil {
		return err
	}
	if holder.Signature.Alg != "Ed25519" {
		return fmt.Errorf("unsupported alg %q", holder.Signature.Alg)
	}
	if holder.Signature.KeyID != keyID(pub) {
		return fmt.Errorf("key_id mismatch (CRYPTO §4)")
	}
	sig, err := b64u.DecodeString(holder.Signature.Value)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	msg, _, err := signingInput(objRaw, domain)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// eventHash implements CRYPTO §10: hash the event object WITHOUT event_hash
// (prev_hash stays in, appearing exactly once); coverage is total.
func eventHash(eventRaw json.RawMessage) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(eventRaw, &top); err != nil {
		return "", err
	}
	delete(top, "event_hash")
	if _, ok := top["prev_hash"]; !ok {
		return "", fmt.Errorf("prev_hash must be present in the hash input")
	}
	rebuilt, err := json.Marshal(top)
	if err != nil {
		return "", err
	}
	canonical, err := canonicalize(rebuilt)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domainEventHash), canonical...))
	return digestString(sum), nil
}

type eventFields struct {
	EventID   string  `json:"event_id"`
	SegmentID string  `json:"segment_id"`
	WriterID  string  `json:"writer_id"`
	Sequence  int64   `json:"sequence"`
	PrevHash  *string `json:"prev_hash"`
	EventHash string  `json:"event_hash"`
}

// verifyChain enforces INV-003/004/005/007 over an ordered event list.
func verifyChain(eventsRaw []json.RawMessage) error {
	if len(eventsRaw) == 0 {
		return fmt.Errorf("empty chain")
	}
	var prev *eventFields
	for i, raw := range eventsRaw {
		var f eventFields
		if err := json.Unmarshal(raw, &f); err != nil {
			return err
		}
		computed, err := eventHash(raw)
		if err != nil {
			return err
		}
		if computed != f.EventHash {
			return fmt.Errorf("event %d: hash mismatch (INV-007)", i)
		}
		if prev == nil {
			if f.Sequence == 0 && f.PrevHash != nil {
				return fmt.Errorf("genesis event must have prev_hash null (INV-003)")
			}
		} else {
			if f.SegmentID != prev.SegmentID || f.WriterID != prev.WriterID {
				return fmt.Errorf("event %d: segment/writer changes mid-chain (INV-005)", i)
			}
			if f.Sequence != prev.Sequence+1 {
				return fmt.Errorf("event %d: sequence not +1 (INV-004)", i)
			}
			if f.PrevHash == nil || *f.PrevHash != prev.EventHash {
				return fmt.Errorf("event %d: prev_hash does not reference predecessor (INV-003)", i)
			}
		}
		cp := f
		prev = &cp
	}
	return nil
}

func anchorInputDigest(closeRaw json.RawMessage) (string, error) { // CRYPTO §14
	canonical, err := canonicalize(closeRaw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domainAnchorInput), canonical...))
	return digestString(sum), nil
}

type writerAuthFields struct {
	OrgID           string         `json:"org_id"`
	AgentID         string         `json:"agent_id"`
	WriterID        string         `json:"writer_id"`
	WriterKeyID     string         `json:"writer_key_id"`
	WriterPublicKey string         `json:"writer_public_key"`
	NotBefore       string         `json:"not_before"`
	NotAfter        string         `json:"not_after"`
	Signature       signatureBlock `json:"signature"`
}

type closeFields struct {
	SegmentID            string         `json:"segment_id"`
	OrgID                string         `json:"org_id"`
	AgentID              string         `json:"agent_id"`
	WriterID             string         `json:"writer_id"`
	SegmentSequence      int64          `json:"segment_sequence"`
	PrevSegmentCloseHash *string        `json:"prev_segment_close_hash"`
	FirstEventHash       string         `json:"first_event_hash"`
	LastEventHash        string         `json:"last_event_hash"`
	EventCount           int64          `json:"event_count"`
	FirstSequence        int64          `json:"first_sequence"`
	LastSequence         int64          `json:"last_sequence"`
	Signature            signatureBlock `json:"signature"`
}

// verifySegmentClose implements INV-006 as amended + CRYPTO §9b/§13:
// close signature → writer key → writer-authorization → org key, plus
// exact chain consistency. Timestamps compare lexicographically, which is
// exact under the single normative format (CRYPTO-006).
func verifySegmentClose(closeRaw, authRaw json.RawMessage,
	eventsRaw []json.RawMessage, keys map[string]ed25519.PublicKey) error {
	var auth writerAuthFields
	if err := json.Unmarshal(authRaw, &auth); err != nil {
		return err
	}
	orgPub, ok := keys[auth.Signature.KeyID]
	if !ok {
		return fmt.Errorf("authorization signer key unknown")
	}
	if err := verifySigned(authRaw, "writer-authorization", orgPub); err != nil {
		return fmt.Errorf("writer authorization: %w", err)
	}
	writerPub, err := b64u.DecodeString(auth.WriterPublicKey)
	if err != nil || len(writerPub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad writer_public_key")
	}
	if keyID(ed25519.PublicKey(writerPub)) != auth.WriterKeyID {
		return fmt.Errorf("writer_key_id does not match writer_public_key (CRYPTO §4)")
	}

	var cl closeFields
	if err := json.Unmarshal(closeRaw, &cl); err != nil {
		return err
	}
	if cl.Signature.KeyID != auth.WriterKeyID {
		return fmt.Errorf("segment close not signed by the authorized writer key")
	}
	if cl.OrgID != auth.OrgID || cl.AgentID != auth.AgentID || cl.WriterID != auth.WriterID {
		return fmt.Errorf("authorization does not cover this org/agent/writer (CRYPTO §9b)")
	}
	if cl.Signature.SignedAt < auth.NotBefore || cl.Signature.SignedAt > auth.NotAfter {
		return fmt.Errorf("segment close signed outside the authorization window")
	}
	if err := verifySigned(closeRaw, "segment-close", ed25519.PublicKey(writerPub)); err != nil {
		return fmt.Errorf("segment close: %w", err)
	}

	if err := verifyChain(eventsRaw); err != nil {
		return err
	}
	var first, last eventFields
	if err := json.Unmarshal(eventsRaw[0], &first); err != nil {
		return err
	}
	if err := json.Unmarshal(eventsRaw[len(eventsRaw)-1], &last); err != nil {
		return err
	}
	if cl.FirstEventHash != first.EventHash || cl.LastEventHash != last.EventHash {
		return fmt.Errorf("close head hashes do not match chain")
	}
	if cl.EventCount != int64(len(eventsRaw)) {
		return fmt.Errorf("event_count does not match chain")
	}
	if cl.FirstSequence != first.Sequence || cl.LastSequence != last.Sequence {
		return fmt.Errorf("close sequences do not match chain")
	}
	for _, raw := range eventsRaw {
		var f eventFields
		_ = json.Unmarshal(raw, &f)
		if f.SegmentID != cl.SegmentID {
			return fmt.Errorf("chain event belongs to a different segment")
		}
	}
	return nil
}

// verifySegmentSequence enforces SEGMENT-010 / INV-023.
func verifySegmentSequence(closesRaw []json.RawMessage) error {
	if len(closesRaw) == 0 {
		return fmt.Errorf("empty segment-close chain")
	}
	var prevDigest string
	for i, raw := range closesRaw {
		var cl closeFields
		if err := json.Unmarshal(raw, &cl); err != nil {
			return err
		}
		if cl.SegmentSequence != int64(i) {
			return fmt.Errorf("close %d: segment_sequence not contiguous from 0 (SEGMENT-010)", i)
		}
		if i == 0 {
			if cl.PrevSegmentCloseHash != nil {
				return fmt.Errorf("first segment must have prev_segment_close_hash null")
			}
		} else if cl.PrevSegmentCloseHash == nil || *cl.PrevSegmentCloseHash != prevDigest {
			return fmt.Errorf("close %d: prev_segment_close_hash mismatch (INV-023)", i)
		}
		d, err := anchorInputDigest(raw)
		if err != nil {
			return err
		}
		prevDigest = d
	}
	return nil
}

// ---- vector runner ---------------------------------------------------------

type vectorCase struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Type      string            `json:"type"`
	VerifyKey string            `json:"verify_key"`
	Object    json.RawMessage   `json:"object"`
	Events    []json.RawMessage `json:"events"`
	Closes    []json.RawMessage `json:"closes"`
	Close     json.RawMessage   `json:"close"`
	WriterAut json.RawMessage   `json:"writer_auth"`
	Value     json.RawMessage   `json:"value"`
	ValueHex  string            `json:"value_hex"`
	Expected  struct {
		Verified                  *bool  `json:"verified"`
		SignatureValue            string `json:"signature_value"`
		CanonicalSigningObjectB64 string `json:"canonical_signing_object_b64u"`
		CanonicalB64              string `json:"canonical_b64u"`
		EventHash                 string `json:"event_hash"`
		Digest                    string `json:"digest"`
	} `json:"expected"`
}

func loadKeys(path string) (map[string]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys map[string]struct {
			SeedHex       string `json:"seed_hex"`
			PublicKeyB64u string `json:"public_key_b64u"`
			KeyID         string `json:"key_id"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := map[string]ed25519.PublicKey{}
	for label, entry := range doc.Keys {
		seed, err := hex.DecodeString(entry.SeedHex)
		if err != nil {
			return nil, err
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		// Self-check the vector file's own consistency (keys.json contract).
		if b64u.EncodeToString(pub) != entry.PublicKeyB64u || keyID(pub) != entry.KeyID {
			return nil, fmt.Errorf("keys.json inconsistent for %s", label)
		}
		out[entry.KeyID] = pub
	}
	return out, nil
}

func runCase(c vectorCase, keys map[string]ed25519.PublicKey) (bool, string) {
	switch c.Kind {
	case "sign-verify":
		pub, ok := keys[c.VerifyKey]
		if !ok {
			return false, "unknown verify_key"
		}
		err := verifySigned(c.Object, c.Type, pub)
		verified := err == nil
		if c.Expected.Verified == nil || verified != *c.Expected.Verified {
			return false, fmt.Sprintf("verified=%v want %v (%v)", verified, c.Expected.Verified, err)
		}
		if verified && c.Expected.CanonicalSigningObjectB64 != "" {
			_, canonical, _ := signingInput(c.Object, "")
			if b64u.EncodeToString(canonical) != c.Expected.CanonicalSigningObjectB64 {
				return false, "canonical signing bytes differ"
			}
		}
		return true, ""
	case "event-hash":
		got, err := eventHash(c.Object)
		if err != nil {
			return false, err.Error()
		}
		if got != c.Expected.EventHash {
			return false, "event_hash differs"
		}
		if c.Expected.CanonicalB64 != "" {
			canonical, _ := canonicalize(c.Object)
			if b64u.EncodeToString(canonical) != c.Expected.CanonicalB64 {
				return false, "canonical bytes differ"
			}
		}
		return true, ""
	case "chain":
		err := verifyChain(c.Events)
		verified := err == nil
		if c.Expected.Verified == nil || verified != *c.Expected.Verified {
			return false, fmt.Sprintf("verified=%v want %v (%v)", verified, c.Expected.Verified, err)
		}
		return true, ""
	case "segment":
		err := verifySegmentClose(c.Close, c.WriterAut, c.Events, keys)
		verified := err == nil
		if c.Expected.Verified == nil || verified != *c.Expected.Verified {
			return false, fmt.Sprintf("verified=%v want %v (%v)", verified, c.Expected.Verified, err)
		}
		return true, ""
	case "segment-chain":
		err := verifySegmentSequence(c.Closes)
		verified := err == nil
		if c.Expected.Verified == nil || verified != *c.Expected.Verified {
			return false, fmt.Sprintf("verified=%v want %v (%v)", verified, c.Expected.Verified, err)
		}
		return true, ""
	case "anchor":
		got, err := anchorInputDigest(c.Object)
		if err != nil {
			return false, err.Error()
		}
		if got != c.Expected.Digest {
			return false, "anchor input digest differs"
		}
		return true, ""
	case "digest-json":
		canonical, err := canonicalize(c.Value)
		if err != nil {
			return false, err.Error()
		}
		sum := sha256.Sum256(append([]byte(domainDigestJSON), canonical...))
		if digestString(sum) != c.Expected.Digest {
			return false, "digest_json differs"
		}
		return true, ""
	case "digest-bytes":
		raw, err := hex.DecodeString(c.ValueHex)
		if err != nil {
			return false, err.Error()
		}
		sum := sha256.Sum256(append([]byte(domainDigestBytes), raw...))
		if digestString(sum) != c.Expected.Digest {
			return false, "digest_bytes differs"
		}
		return true, ""
	}
	return false, "unknown kind " + c.Kind
}

func main() {
	vectorDir := flag.String("vectors", "../../spec/vectors/v0.1", "vector directory")
	flag.Parse()

	keys, err := loadKeys(filepath.Join(*vectorDir, "keys.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "keys:", err)
		os.Exit(2)
	}
	data, err := os.ReadFile(filepath.Join(*vectorDir, "vectors.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "vectors:", err)
		os.Exit(2)
	}
	var doc struct {
		Cases []vectorCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(2)
	}
	failures := 0
	for _, c := range doc.Cases {
		ok, detail := runCase(c, keys)
		status := "PASS"
		if !ok {
			status = "FAIL " + detail
			failures++
		}
		fmt.Printf("%s: %s\n", c.Name, status)
	}
	fmt.Printf("TOTAL: %d/%d\n", len(doc.Cases)-failures, len(doc.Cases))
	if failures > 0 {
		os.Exit(1)
	}
	_ = strings.TrimSpace("")
}
