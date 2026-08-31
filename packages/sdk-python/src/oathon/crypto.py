"""Oathon v0.1 cryptographic core.

Byte-exact implementation of CRYPTOGRAPHY.md. Every construction here is
covered by known-answer vectors under spec/vectors/v0.1/ (CRYPTO §15).
"""

from __future__ import annotations

import base64
import copy
import hashlib
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .jsonutil import check_finite

# CRYPTOGRAPHY.md §5 — domain separation strings. The trailing 0x00 byte is
# part of the domain (single byte, not the characters backslash+zero).
DOMAIN_MANDATE = b"WARRANT-MANDATE-SIGN-V0.1\x00"
DOMAIN_REVOCATION = b"WARRANT-REVOCATION-SIGN-V0.1\x00"
DOMAIN_KEY_TRANSITION = b"WARRANT-KEY-TRANSITION-SIGN-V0.1\x00"
DOMAIN_EVENT_HASH = b"WARRANT-EVENT-HASH-V0.1\x00"
DOMAIN_SEGMENT = b"WARRANT-SEGMENT-SIGN-V0.1\x00"
DOMAIN_DIGEST_JSON = b"WARRANT-DIGEST-JSON-V0.1\x00"
DOMAIN_DIGEST_BYTES = b"WARRANT-DIGEST-BYTES-V0.1\x00"
DOMAIN_ANCHOR_INPUT = b"WARRANT-ANCHOR-INPUT-V0.1\x00"
DOMAIN_KEY_GENESIS = b"WARRANT-KEY-GENESIS-SIGN-V0.1\x00"
DOMAIN_WRITER_AUTH = b"WARRANT-WRITER-AUTH-SIGN-V0.1\x00"

SIGN_DOMAINS: dict[str, bytes] = {
    "mandate": DOMAIN_MANDATE,
    "revocation": DOMAIN_REVOCATION,
    "key-transition": DOMAIN_KEY_TRANSITION,
    "segment-close": DOMAIN_SEGMENT,
    "key-genesis": DOMAIN_KEY_GENESIS,
    "writer-authorization": DOMAIN_WRITER_AUTH,
}


class VerificationError(Exception):
    """A cryptographic check failed. The message states which one."""


def b64u_encode(raw: bytes) -> str:
    """RFC 4648 base64url without padding (CRYPTO-005)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    if "=" in text:
        raise VerificationError("base64url value must not contain padding")
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:  # noqa: BLE001 - normalize decode errors
        raise VerificationError(f"invalid base64url: {exc}") from exc


def canonicalize(value: Any) -> bytes:
    """RFC 8785 JCS canonical UTF-8 bytes (CRYPTO-003/004)."""
    check_finite(value)
    return rfc8785.dumps(value)


def digest_string(raw32: bytes) -> str:
    """Encode a 32-byte SHA-256 digest as sha256:<b64u> (CRYPTO §3)."""
    if len(raw32) != 32:
        raise VerificationError("digest must be exactly 32 bytes")
    return "sha256:" + b64u_encode(raw32)


def decode_digest_string(text: str) -> bytes:
    if not text.startswith("sha256:"):
        raise VerificationError("digest string must start with 'sha256:'")
    raw = b64u_decode(text[len("sha256:"):])
    if len(raw) != 32:
        raise VerificationError("decoded digest must be exactly 32 bytes")
    return raw


def key_id_for_public_key(raw_public_key: bytes) -> str:
    """CRYPTO §4: "ed25519:" + b64u(SHA256(raw 32 public-key bytes))."""
    if len(raw_public_key) != 32:
        raise VerificationError("Ed25519 public key must be 32 raw bytes")
    return "ed25519:" + b64u_encode(hashlib.sha256(raw_public_key).digest())


def digest_json(value: Any) -> str:
    """CRYPTO §11 structured JSON digest helper."""
    raw = hashlib.sha256(DOMAIN_DIGEST_JSON + canonicalize(value)).digest()
    return digest_string(raw)


def digest_bytes(value: bytes) -> str:
    """CRYPTO §12 byte digest helper. Caller must pass bytes explicitly."""
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("digest_bytes requires bytes; use digest_json for JSON values")
    raw = hashlib.sha256(DOMAIN_DIGEST_BYTES + bytes(value)).digest()
    return digest_string(raw)


def event_hash(event_without_event_hash: dict[str, Any]) -> str:
    """CRYPTO §10. Input must contain prev_hash and must NOT contain event_hash."""
    if "event_hash" in event_without_event_hash:
        raise VerificationError("event_hash must be absent from the hash input")
    if "prev_hash" not in event_without_event_hash:
        raise VerificationError("prev_hash must be present in the hash input")
    raw = hashlib.sha256(
        DOMAIN_EVENT_HASH + canonicalize(event_without_event_hash)
    ).digest()
    return digest_string(raw)


def anchor_input_digest(segment_close_with_signature: dict[str, Any]) -> str:
    """CRYPTO §14: digest of the complete signed segment-close record."""
    raw = hashlib.sha256(
        DOMAIN_ANCHOR_INPUT + canonicalize(segment_close_with_signature)
    ).digest()
    return digest_string(raw)


def signing_input(obj: dict[str, Any], domain: bytes) -> bytes:
    """CRYPTO §6: DOMAIN || UTF8(JCS(object minus signature.value))."""
    if "signature" not in obj or not isinstance(obj["signature"], dict):
        raise VerificationError("object has no signature object")
    x = copy.deepcopy(obj)
    x["signature"].pop("value", None)
    return domain + canonicalize(x)


def sign_object(obj: dict[str, Any], domain: bytes, private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Fill signature.value. signature.alg/key_id/signed_at must be preset."""
    sig = private_key.sign(signing_input(obj, domain))
    signed = copy.deepcopy(obj)
    signed["signature"]["value"] = b64u_encode(sig)
    return signed


def verify_object(obj: dict[str, Any], domain: bytes, raw_public_key: bytes) -> None:
    """Verify a signed object per CRYPTO §6. Raises VerificationError on failure."""
    sig_block = obj.get("signature")
    if not isinstance(sig_block, dict):
        raise VerificationError("missing signature object")
    if sig_block.get("alg") != "Ed25519":
        raise VerificationError("unsupported signature alg")
    expected_key_id = key_id_for_public_key(raw_public_key)
    if sig_block.get("key_id") != expected_key_id:
        raise VerificationError("key_id mismatch for provided public key")
    value = sig_block.get("value")
    if not isinstance(value, str):
        raise VerificationError("missing signature value")
    sig = b64u_decode(value)
    try:
        Ed25519PublicKey.from_public_bytes(raw_public_key).verify(
            sig, signing_input(obj, domain)
        )
    except InvalidSignature as exc:
        raise VerificationError("signature verification failed") from exc


def private_key_from_seed(seed32: bytes) -> Ed25519PrivateKey:
    if len(seed32) != 32:
        raise VerificationError("Ed25519 seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed32)


def public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
