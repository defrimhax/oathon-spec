"""RFC 6901 JSON Pointer resolution (used for evaluation_metadata extraction
per MANDATE-014 / EVENT-009)."""

from __future__ import annotations

from typing import Any

_MISSING = object()


def resolve_pointer(doc: Any, pointer: str) -> Any:
    """Return the value at `pointer`, or None when the path is absent
    (EVENT-009: absent evaluable fields are recorded as null)."""
    if not pointer.startswith("/"):
        raise ValueError(f"invalid JSON Pointer: {pointer!r}")
    current = doc
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(token, _MISSING)
        elif isinstance(current, list):
            try:
                current = current[int(token)]
            except (ValueError, IndexError):
                current = _MISSING
        else:
            current = _MISSING
        if current is _MISSING:
            return None
    return current
