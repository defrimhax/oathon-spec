"""Org key-history verification (KEY-001..010, INV-012, INV-021).

Builds the trusted key set for an organization by walking its append-only
key records: one self-signed genesis (CRYPTO §9a), then transitions
(CRYPTO §9). Historical keys are always retained (INV-012). Administrative
recovery breaks cryptographic continuity and is reported, never hidden
(KEY-006, SECURITY.md §6).
"""

from __future__ import annotations

from typing import Any

from . import crypto
from .crypto import VerificationError
from .validate import validate_object
from .verify import KeySet, verify_signed


def build_org_keyring(records: list[dict[str, Any]]) -> dict[str, Any]:
    """records: ordered [{"record_type": "genesis"|"transition", "record": {...}}].

    Returns {"keyset": KeySet, "active_key_id": str, "continuity_breaks": [...]}.
    Raises VerificationError on an invalid history.
    """
    keyset = KeySet()
    continuity_breaks: list[dict[str, Any]] = []
    active_key_id: str | None = None

    for i, entry in enumerate(records):
        record_type, record = entry["record_type"], entry["record"]
        if i == 0:
            if record_type != "genesis":
                raise VerificationError("key history must start with a genesis record")
            errors = validate_object(record, "key-genesis")
            if errors:
                raise VerificationError(f"invalid key-genesis: {errors}")
            pub = crypto.b64u_decode(record["public_key"])
            if crypto.key_id_for_public_key(pub) != record["key_id"]:
                raise VerificationError("genesis key_id does not match public_key")
            crypto.verify_object(record, crypto.DOMAIN_KEY_GENESIS, pub)  # self-signed
            keyset.keys[record["key_id"]] = pub
            active_key_id = record["key_id"]
            continue

        if record_type != "transition":
            raise VerificationError("only one genesis record is allowed (KEY-010)")
        errors = validate_object(record, "key-transition")
        if errors:
            raise VerificationError(f"invalid key-transition: {errors}")
        new_pub = crypto.b64u_decode(record["new_public_key"])
        if crypto.key_id_for_public_key(new_pub) != record["new_key_id"]:
            raise VerificationError("transition new_key_id does not match new_public_key")

        if record.get("continuity") == "administrative-recovery":
            # Old key unavailable: record is signed by the NEW key and the
            # break is recorded (KEY-006); history is preserved (KEY-008).
            crypto.verify_object(record, crypto.DOMAIN_KEY_TRANSITION, new_pub)
            continuity_breaks.append({
                "transition_id": record["transition_id"],
                "old_key_id": record["old_key_id"],
                "new_key_id": record["new_key_id"],
                "effective_at": record["effective_at"],
            })
        else:
            # KEY-005: normal rotation must be signed by the previous key.
            if record["old_key_id"] not in keyset.keys:
                raise VerificationError("transition old_key_id unknown in history")
            if record["signature"].get("key_id") != record["old_key_id"]:
                raise VerificationError("normal rotation must be signed by the old key")
            verify_signed(record, "key-transition", keyset)
        keyset.keys[record["new_key_id"]] = new_pub  # INV-012: keep all keys
        active_key_id = record["new_key_id"]

    if active_key_id is None:
        raise VerificationError("empty key history")
    return {
        "keyset": keyset,
        "active_key_id": active_key_id,
        "continuity_breaks": continuity_breaks,
    }
