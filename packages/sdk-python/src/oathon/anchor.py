"""RFC 3161 anchoring (Phase 5; ANCHOR-001..008, CRYPTOGRAPHY.md §14).

The timestamped datum is DOMAIN_ANCHOR_INPUT ‖ JCS(signed segment-close):
its SHA-256 is both our anchor-input digest and the RFC 3161 messageImprint.
Verification (ANCHOR-007) checks: PKIStatus granted, message imprint, nonce
(ours are always sent), token signature and certificate chain to the given
TSA root(s) — via rfc3161-client (Trail of Bits; SEC-010 review in
verification/phase-5.md). The raw response bytes are always retained.

INV-015 applies: a verified receipt proves the digest existed by the TSA
timestamp under that TSA's policy — nothing more.
"""

from __future__ import annotations

from typing import Any

from cryptography import x509
from rfc3161_client import (
    HashAlgorithm,
    TimestampRequestBuilder,
    VerifierBuilder,
    decode_timestamp_response,
)
from rfc3161_client import VerificationError as TsaVerificationError

from . import crypto


class AnchorError(Exception):
    """Anchor request/verification failure. Never mutates the segment
    (ANCHOR-004)."""


def anchor_data(segment_close: dict[str, Any]) -> bytes:
    """The exact bytes whose SHA-256 is the messageImprint (CRYPTO §14)."""
    return crypto.DOMAIN_ANCHOR_INPUT + crypto.canonicalize(segment_close)


def build_anchor_request(segment_close: dict[str, Any]) -> dict[str, Any]:
    """Build a TimeStampReq with SHA-256 imprint, fresh nonce, certReq=true."""
    data = anchor_data(segment_close)
    request = (
        TimestampRequestBuilder()
        .data(data)
        .hash_algorithm(HashAlgorithm.SHA256)
        .build()
    )
    return {
        "der": request.as_bytes(),
        "nonce": request.nonce,
        "anchor_input": crypto.anchor_input_digest(segment_close),
    }


def tsa_identity_from_receipt(response_der: bytes) -> str:
    """Signer identity of a stored receipt, derived from the certificate
    embedded in the response (never hardcoded): the leaf is identified via
    the SignerInfo's issuerAndSerialNumber, exactly as verification does.
    Returns the certificate's subject (RFC 4514), or an explicit
    'unknown …' string when the receipt cannot be parsed."""
    try:
        response = decode_timestamp_response(response_der)
        signer_infos = list(response.signed_data.signer_infos)
        if len(signer_infos) != 1:
            return "unknown (unexpected signer count)"
        sid = signer_infos[0]
        for cert_der in response.signed_data.certificates:
            cert = x509.load_der_x509_certificate(cert_der)
            if cert.issuer == sid.issuer and cert.serial_number == sid.serial_number:
                return cert.subject.rfc4514_string()
        return "unknown (signer certificate not embedded)"
    except Exception:  # noqa: BLE001 — identity display must never crash a report
        return "unknown (unparseable receipt)"


def verify_anchor_receipt(
    response_der: bytes,
    segment_close: dict[str, Any],
    nonce: int | None,
    tsa_root_pems: list[bytes],
    tsa_certificate_pem: bytes,
) -> dict[str, Any]:
    """Full ANCHOR-007 verification. Raises AnchorError on any failure.

    Trust binding: rfc3161-client's pkcs7 verification uses a certificate
    POOL that includes the response's own embedded certificates, so the
    roots alone do not pin trust. We therefore REQUIRE the expected TSA
    signing certificate (`tsa_certificate_pem`): the verifier enforces that
    the response's signer certificate equals the pinned one, plus PKIStatus
    granted, critical timeStamping EKU, certificate time-validity at
    gen_time, nonce equality, and imprint equality over our exact bytes.
    This matches SECURITY.md §2: the TSA is trusted exactly as selected and
    pinned, per its certificate policy.

    Returns {"gen_time", "policy", "anchor_input"} for persistence alongside
    the raw response bytes.
    """
    try:
        response = decode_timestamp_response(response_der)
    except Exception as exc:  # noqa: BLE001 — malformed DER must fail cleanly
        raise AnchorError(f"malformed timestamp response: {exc}") from exc

    builder = VerifierBuilder().tsa_certificate(
        x509.load_pem_x509_certificate(tsa_certificate_pem)
    )
    for pem in tsa_root_pems:
        builder = builder.add_root_certificate(x509.load_pem_x509_certificate(pem))
    if nonce is not None:
        builder = builder.nonce(nonce)
    verifier = builder.build()
    try:
        # verify_message = PKIStatus granted + cert chain to roots + leaf
        # cert checks + nonce + message imprint over our exact bytes.
        verifier.verify_message(response, anchor_data(segment_close))
    except TsaVerificationError as exc:
        raise AnchorError(f"timestamp verification failed: {exc}") from exc

    info = response.tst_info
    return {
        "gen_time": info.gen_time.isoformat(),
        "policy": str(info.policy.dotted_string) if info.policy else None,
        "anchor_input": crypto.anchor_input_digest(segment_close),
    }
