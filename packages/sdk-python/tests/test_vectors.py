"""Known-answer vector tests (TEST-003): re-verify every committed vector
from spec/vectors/v0.1/ independently of the generator, including expected
byte and signature equality, and re-derive the test keys from their seeds.
"""

import pytest

from oathon import crypto
from oathon.crypto import VerificationError
from oathon.verify import verify_chain, verify_segment_close, verify_segment_sequence, verify_signed


def _cases(vectors, kind):
    return [c for c in vectors["cases"] if c["kind"] == kind]


def test_keys_rederivable_from_seeds(test_keys):
    import hashlib

    for label, entry in test_keys["keys"].items():
        seed = hashlib.sha256(f"WARRANT-INSECURE-TEST-KEY:{label}".encode()).digest()
        assert seed.hex() == entry["seed_hex"]
        priv = crypto.private_key_from_seed(seed)
        pub = crypto.public_key_bytes(priv)
        assert crypto.b64u_encode(pub) == entry["public_key_b64u"]
        assert crypto.key_id_for_public_key(pub) == entry["key_id"]


def test_sign_verify_vectors(vectors, keyset):
    cases = _cases(vectors, "sign-verify")
    assert len(cases) >= 8
    for case in cases:
        obj, obj_type = case["object"], case["type"]
        expected = case["expected"]
        # Force verification against the vector's designated key, even when it
        # differs from the object's own key_id (wrong-key case).
        domain = crypto.SIGN_DOMAINS[obj_type]
        pub = keyset.public_key(case["verify_key"])
        if expected["verified"]:
            crypto.verify_object(obj, domain, pub)
            if "signature_value" in expected:
                assert obj["signature"]["value"] == expected["signature_value"]
        else:
            with pytest.raises(VerificationError):
                crypto.verify_object(obj, domain, pub)


def test_mandate_canonical_bytes(vectors):
    case = next(c for c in vectors["cases"] if c["name"] == "mandate-valid")
    expected = case["expected"]["canonical_signing_object_b64u"]
    recomputed = crypto.b64u_encode(crypto.signing_input(case["object"], b""))
    assert recomputed == expected


def test_deterministic_resigning_reproduces_signature(vectors, test_keys):
    """Ed25519 is deterministic: re-signing must reproduce the committed value."""
    import hashlib

    case = next(c for c in vectors["cases"] if c["name"] == "mandate-valid")
    obj = case["object"]
    key_label = next(
        label for label, k in test_keys["keys"].items()
        if k["key_id"] == obj["signature"]["key_id"]
    )
    seed = hashlib.sha256(f"WARRANT-INSECURE-TEST-KEY:{key_label}".encode()).digest()
    priv = crypto.private_key_from_seed(seed)
    resigned = crypto.sign_object(obj, crypto.DOMAIN_MANDATE, priv)
    assert resigned["signature"]["value"] == obj["signature"]["value"]


def test_event_hash_vectors(vectors):
    for case in _cases(vectors, "event-hash"):
        recomputed = crypto.event_hash(case["object"])
        assert recomputed == case["expected"]["event_hash"], case["name"]
        if "canonical_b64u" in case["expected"]:
            assert crypto.b64u_encode(crypto.canonicalize(case["object"])) == \
                case["expected"]["canonical_b64u"], case["name"]


def test_chain_vectors(vectors):
    for case in _cases(vectors, "chain"):
        if case["expected"]["verified"]:
            verify_chain(case["events"])
        else:
            with pytest.raises(VerificationError):
                verify_chain(case["events"])


def test_digest_vectors(vectors):
    for case in _cases(vectors, "digest-json"):
        assert crypto.digest_json(case["value"]) == case["expected"]["digest"]
    for case in _cases(vectors, "digest-bytes"):
        assert crypto.digest_bytes(bytes.fromhex(case["value_hex"])) == \
            case["expected"]["digest"]


def test_digest_domain_separation():
    """The same logical content must digest differently as JSON vs bytes."""
    value = {"a": 1}
    as_json = crypto.digest_json(value)
    as_bytes = crypto.digest_bytes(crypto.canonicalize(value))
    assert as_json != as_bytes


def test_segment_vectors(vectors, keyset):
    for case in _cases(vectors, "segment"):
        args = (case["close"], case["events"], case["writer_auth"], keyset)
        if case["expected"]["verified"]:
            verify_segment_close(*args)
        else:
            with pytest.raises(VerificationError):
                verify_segment_close(*args)


def test_anchor_vectors(vectors):
    for case in _cases(vectors, "anchor"):
        assert crypto.anchor_input_digest(case["object"]) == case["expected"]["digest"]


def test_segment_chain_vectors(vectors):
    for case in _cases(vectors, "segment-chain"):
        if case["expected"]["verified"]:
            verify_segment_sequence(case["closes"])
        else:
            with pytest.raises(VerificationError):
                verify_segment_sequence(case["closes"])


def test_expired_writer_authorization_rejected(vectors, keyset):
    case = next(c for c in vectors["cases"] if c["name"] == "segment-close-valid")
    with pytest.raises(VerificationError, match="authorization window"):
        verify_segment_close(
            case["close"], case["events"], case["writer_auth"], keyset,
            at="2027-01-01T00:00:00.000Z",
        )


def test_all_crypto15_constructions_covered(vectors):
    """CRYPTOGRAPHY.md §15 coverage check for the committed vector set."""
    names = {c["name"] for c in vectors["cases"]}
    required = {
        "mandate-valid", "mandate-modified-field", "mandate-modified-signing-metadata",
        "mandate-wrong-public-key", "revocation-valid", "key-transition-valid",
        "event-genesis", "event-second-chained", "chain-event-mutation",
        "chain-predecessor-mutation", "event-unicode", "digest-json", "digest-bytes",
        "segment-close-valid", "anchor-input", "key-genesis-valid",
        "writer-authorization-valid", "segment-chain-valid",
        "segment-close-wrong-writer-auth",
    }
    assert required <= names
