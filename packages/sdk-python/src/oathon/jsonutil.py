"""Strict JSON parsing per CRYPTOGRAPHY.md §2.

Rejects duplicate object keys, NaN, Infinity, -Infinity before any
canonicalization or validation happens (CRYPTO §2). The stdlib parser
silently keeps the last duplicate key and accepts non-finite constants,
so both must be intercepted here.
"""

from __future__ import annotations

import json
import math
from typing import Any


class StrictJSONError(ValueError):
    """Input violates the protocol's JSON restrictions (CRYPTOGRAPHY.md §2)."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise StrictJSONError(f"duplicate object key: {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    raise StrictJSONError(f"non-finite JSON constant rejected: {name}")


def loads_strict(text: str | bytes) -> Any:
    """Parse JSON text, enforcing CRYPTOGRAPHY.md §2 restrictions."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_constant,
    )


def check_finite(value: Any, path: str = "$") -> None:
    """Reject NaN/Infinity in already-parsed structures (defense in depth)."""
    if isinstance(value, float) and not math.isfinite(value):
        raise StrictJSONError(f"non-finite number at {path}")
    if isinstance(value, dict):
        for k, v in value.items():
            check_finite(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            check_finite(v, f"{path}[{i}]")
