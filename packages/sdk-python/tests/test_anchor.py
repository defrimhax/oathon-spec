"""Phase 5 anchor tests. The committed fixture is a REAL freetsa.org receipt
for the normative segment-close vector, obtained by actual external
execution on 2026-08-31 (see verification/phase-5.md).

Required scenarios: correct imprint, incorrect imprint, wrong nonce,
malformed response, invalid signature (tampered bytes / wrong pinned TSA
certificate)."""

import base64
import hashlib
import json

import pytest

from oathon import crypto
from oathon.anchor import (
    AnchorError,
    anchor_data,
    build_anchor_request,
    verify_anchor_receipt,
)
from oathon.validate import find_spec_dir

TSA_DIR = find_spec_dir() / "vectors" / "v0.1" / "tsa"


@pytest.fixture(scope="module")
def fixture():
    return json.loads((TSA_DIR / "freetsa-receipt.json").read_text())


@pytest.fixture(scope="module")
def root_pem():
    return (TSA_DIR / "freetsa-cacert.pem").read_bytes()


@pytest.fixture(scope="module")
def tsa_cert_pem():
    return (TSA_DIR / "freetsa-tsa.pem").read_bytes()


@pytest.fixture(scope="module")
def segment_close(vectors):
    return next(c for c in vectors["cases"] if c["name"] == "anchor-input")["object"]


def test_request_imprint_is_anchor_input_digest(segment_close):
    """CRYPTO §14: messageImprint == SHA-256 of domain-separated close bytes."""
    request = build_anchor_request(segment_close)
    expected = hashlib.sha256(anchor_data(segment_close)).digest()
    assert crypto.decode_digest_string(request["anchor_input"]) == expected
    assert request["nonce"] is not None  # AM-7 resolution: nonce always sent


def test_real_receipt_verifies(fixture, segment_close, root_pem, tsa_cert_pem):
    result = verify_anchor_receipt(
        base64.b64decode(fixture["response_der_b64"]),
        segment_close, fixture["nonce"], [root_pem], tsa_cert_pem,
    )
    assert result["anchor_input"] == fixture["anchor_input"]
    assert result["gen_time"].startswith("2026-08-31")


def test_incorrect_imprint_rejected(fixture, segment_close, root_pem, tsa_cert_pem):
    """The receipt must not verify against a different segment close."""
    other = json.loads(json.dumps(segment_close))
    other["event_count"] = 99
    with pytest.raises(AnchorError, match="verification failed"):
        verify_anchor_receipt(
            base64.b64decode(fixture["response_der_b64"]),
            other, fixture["nonce"], [root_pem], tsa_cert_pem,
        )


def test_wrong_nonce_rejected(fixture, segment_close, root_pem, tsa_cert_pem):
    with pytest.raises(AnchorError):
        verify_anchor_receipt(
            base64.b64decode(fixture["response_der_b64"]),
            segment_close, fixture["nonce"] + 1, [root_pem], tsa_cert_pem,
        )


def test_malformed_response_rejected(segment_close, root_pem, tsa_cert_pem):
    with pytest.raises(AnchorError, match="malformed"):
        verify_anchor_receipt(
            b"\x30\x03\x02\x01", segment_close, None, [root_pem], tsa_cert_pem,
        )


def test_tampered_response_rejected(fixture, segment_close, root_pem, tsa_cert_pem):
    der = bytearray(base64.b64decode(fixture["response_der_b64"]))
    der[-40] ^= 0xFF  # flip a byte inside the signature/cert region
    with pytest.raises(AnchorError):
        verify_anchor_receipt(
            bytes(der), segment_close, fixture["nonce"], [root_pem], tsa_cert_pem,
        )


def test_wrong_pinned_tsa_certificate_rejected(fixture, segment_close, root_pem):
    """Trust binding: a receipt signed by a different TSA than the pinned
    certificate must fail, even though the response embeds its own certs."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Fake TSA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(4711)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2040, 1, 1))
        .sign(key, hashes.SHA256())
    )
    fake_pem = cert.public_bytes(serialization.Encoding.PEM)
    with pytest.raises(AnchorError):
        verify_anchor_receipt(
            base64.b64decode(fixture["response_der_b64"]),
            segment_close, fixture["nonce"], [root_pem], fake_pem,
        )
