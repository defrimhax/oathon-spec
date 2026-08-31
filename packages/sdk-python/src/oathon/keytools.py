"""Client-side key utilities (KEY-002/003: keys are generated client-side and
never sent to the server). Builders for key-genesis and writer-authorization
records per CRYPTOGRAPHY.md §9a/§9b.
"""

from __future__ import annotations

import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import crypto, ids


def generate_signing_key() -> tuple[Ed25519PrivateKey, bytes, str]:
    """Return (private_key, raw_public_bytes, key_id)."""
    seed = os.urandom(32)
    priv = crypto.private_key_from_seed(seed)
    pub = crypto.public_key_bytes(priv)
    return priv, pub, crypto.key_id_for_public_key(pub)


def build_key_genesis(org_id: str, private_key: Ed25519PrivateKey, ts_ns: int | None = None) -> dict[str, Any]:
    """Self-signed key-genesis record (CRYPTO §9a, KEY-010)."""
    pub = crypto.public_key_bytes(private_key)
    key_id = crypto.key_id_for_public_key(pub)
    at = ids.protocol_timestamp(ts_ns)
    record = {
        "genesis_id": ids.uuid7(ts_ns),
        "spec_version": "0.1",
        "org_id": org_id,
        "key_id": key_id,
        "public_key": crypto.b64u_encode(pub),
        "created_at": at,
        "signature": {"alg": "Ed25519", "key_id": key_id, "signed_at": at},
    }
    return crypto.sign_object(record, crypto.DOMAIN_KEY_GENESIS, private_key)


def build_writer_authorization(
    *,
    org_private_key: Ed25519PrivateKey,
    org_id: str,
    agent_id: str,
    writer_id: str,
    writer_public_key: bytes,
    not_before: str,
    not_after: str,
    ts_ns: int | None = None,
) -> dict[str, Any]:
    """Writer-authorization record signed by the org key (CRYPTO §9b, KEY-009)."""
    org_pub = crypto.public_key_bytes(org_private_key)
    record = {
        "authorization_id": ids.uuid7(ts_ns),
        "spec_version": "0.1",
        "org_id": org_id,
        "agent_id": agent_id,
        "writer_id": writer_id,
        "writer_key_id": crypto.key_id_for_public_key(writer_public_key),
        "writer_public_key": crypto.b64u_encode(writer_public_key),
        "not_before": not_before,
        "not_after": not_after,
        "signature": {
            "alg": "Ed25519",
            "key_id": crypto.key_id_for_public_key(org_pub),
            "signed_at": ids.protocol_timestamp(ts_ns),
        },
    }
    return crypto.sign_object(record, crypto.DOMAIN_WRITER_AUTH, org_private_key)
