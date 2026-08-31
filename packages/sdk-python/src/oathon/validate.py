"""`oathon validate` core: schema validation + semantic rules.

Schema checks come from the normative files under spec/. Semantic checks
enforce the freeze rules a JSON Schema cannot express:
MANDATE-014 (constraint paths ⊆ evaluable_fields), MANDATE-015 (`in`
operand type), validity ordering, and key-genesis self-signing shape.
"""

from __future__ import annotations

import functools
import json
import os
from pathlib import Path
from typing import Any

import jsonschema

from .jsonutil import StrictJSONError, loads_strict

SCHEMA_FILES = {
    "mandate": "mandate/v0.1/mandate.schema.json",
    "revocation": "mandate/v0.1/revocation.schema.json",
    "key-genesis": "keys/v0.1/key-genesis.schema.json",
    "key-transition": "keys/v0.1/key-transition.schema.json",
    "writer-authorization": "keys/v0.1/writer-authorization.schema.json",
    "event": "evidence/v0.1/event.schema.json",
    "segment-close": "evidence/v0.1/segment-close.schema.json",
}

# Fields whose presence identifies the object type (for --type auto-detection).
_DETECT_ORDER = [
    ("mandate", "mandate_id"),
    ("revocation", "revocation_id"),
    ("key-genesis", "genesis_id"),
    ("key-transition", "transition_id"),
    ("writer-authorization", "authorization_id"),
    ("event", "event_id"),
    ("segment-close", "first_event_hash"),
]


def find_spec_dir(start: Path | None = None) -> Path:
    """Locate the schema directory: OATHON_SPEC_DIR, else the repo's spec/,
    else the copy packaged inside the wheel (oathon/specdata)."""
    env = os.environ.get("OATHON_SPEC_DIR")
    if env:
        return Path(env)
    here = (start or Path(__file__).resolve()).parent
    for candidate in [here, *here.parents]:
        spec = candidate / "spec"
        if (spec / "mandate" / "v0.1" / "mandate.schema.json").exists():
            return spec
    packaged = Path(__file__).resolve().parent / "specdata"
    if (packaged / "mandate" / "v0.1" / "mandate.schema.json").exists():
        return packaged
    raise FileNotFoundError(
        "spec/ directory not found; set OATHON_SPEC_DIR to the repo's spec directory"
    )


@functools.lru_cache(maxsize=None)
def load_schema(object_type: str) -> dict[str, Any]:
    rel = SCHEMA_FILES[object_type]
    path = find_spec_dir() / rel
    return json.loads(path.read_text())


def detect_type(obj: dict[str, Any]) -> str:
    for object_type, marker in _DETECT_ORDER:
        if marker in obj:
            return object_type
    raise ValueError("could not detect object type; pass --type explicitly")


def _semantic_errors_mandate(obj: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    authority = obj.get("authority", {})
    evaluable: dict[str, set[str]] = {
        entry.get("action"): set(entry.get("evaluable_fields", []))
        for entry in authority.get("permitted_actions", [])
        if isinstance(entry, dict)
    }
    permitted = set(evaluable)
    forbidden = set(authority.get("forbidden_actions", []))

    overlap = permitted & forbidden
    if overlap:
        errors.append(f"actions both permitted and forbidden: {sorted(overlap)}")

    def check_comparison(comp: dict[str, Any], action: str | None, where: str) -> None:
        op = comp.get("op")
        value = comp.get("value")
        if op == "in":
            # MANDATE-015: array of same-type scalars, no bool/number mixing.
            if isinstance(value, list) and value:
                kinds = {
                    "bool" if isinstance(v, bool) else type(v).__name__
                    for v in value
                }
                if len(kinds) != 1 or kinds & {"NoneType"}:
                    errors.append(
                        f"{where}: 'in' operand must be same-type non-null scalars (MANDATE-015)"
                    )
        path = comp.get("path")
        if action is not None and path is not None:
            fields = evaluable.get(action)
            if fields is None:
                errors.append(f"{where}: action {action!r} is not a permitted action")
            elif path not in fields:
                errors.append(
                    f"{where}: path {path!r} not in evaluable_fields of {action!r} (MANDATE-014)"
                )

    for i, constraint in enumerate(authority.get("constraints", [])):
        if not isinstance(constraint, dict):
            continue
        if constraint.get("op") == "max_count_per_utc_day":
            action = constraint.get("action")
            if action is not None and action not in permitted:
                errors.append(
                    f"constraints[{i}]: action {action!r} is not a permitted action"
                )
            continue
        check_comparison(constraint, constraint.get("action"), f"constraints[{i}]")

    for i, trigger in enumerate(authority.get("approval_triggers", [])):
        if not isinstance(trigger, dict):
            continue
        action = trigger.get("action")
        for j, comp in enumerate(trigger.get("all", [])):
            if isinstance(comp, dict):
                check_comparison(comp, action, f"approval_triggers[{i}].all[{j}]")

    validity = obj.get("validity", {})
    nb, na = validity.get("not_before"), validity.get("not_after")
    if isinstance(nb, str) and isinstance(na, str) and nb >= na:
        errors.append("validity.not_before must be strictly before validity.not_after")
    return errors


def _semantic_errors_key_genesis(obj: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sig = obj.get("signature", {})
    if obj.get("key_id") != sig.get("key_id"):
        errors.append("key-genesis must be self-signed: signature.key_id must equal key_id")
    return errors


def _semantic_errors_writer_auth(obj: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    nb, na = obj.get("not_before"), obj.get("not_after")
    if isinstance(nb, str) and isinstance(na, str) and nb >= na:
        errors.append("not_before must be strictly before not_after")
    return errors


def _semantic_errors_segment_close(obj: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    first, last = obj.get("first_sequence"), obj.get("last_sequence")
    count = obj.get("event_count")
    if all(isinstance(v, int) for v in (first, last, count)):
        if last < first:
            errors.append("last_sequence must be >= first_sequence")
        elif count != last - first + 1:
            errors.append("event_count must equal last_sequence - first_sequence + 1")
    if obj.get("segment_sequence") == 0 and obj.get("prev_segment_close_hash") is not None:
        errors.append("segment_sequence 0 requires prev_segment_close_hash null (SEGMENT-010)")
    if isinstance(obj.get("segment_sequence"), int) and obj["segment_sequence"] > 0 \
            and obj.get("prev_segment_close_hash") is None:
        errors.append("non-first segment requires prev_segment_close_hash (SEGMENT-010)")
    return errors


_SEMANTIC_CHECKS = {
    "mandate": _semantic_errors_mandate,
    "key-genesis": _semantic_errors_key_genesis,
    "writer-authorization": _semantic_errors_writer_auth,
    "segment-close": _semantic_errors_segment_close,
}


def validate_object(obj: dict[str, Any], object_type: str) -> list[str]:
    """Return a list of validation errors (empty = valid)."""
    validator = jsonschema.Draft202012Validator(load_schema(object_type))
    errors = [
        f"schema: {'/'.join(str(p) for p in e.absolute_path) or '$'}: {e.message}"
        for e in validator.iter_errors(obj)
    ]
    check = _SEMANTIC_CHECKS.get(object_type)
    if check and not errors:
        errors.extend(check(obj))
    return errors


def validate_text(text: str | bytes, object_type: str | None = None) -> tuple[str | None, list[str]]:
    """Strict-parse and validate raw JSON text. Returns (detected_type, errors)."""
    try:
        obj = loads_strict(text)
    except StrictJSONError as exc:
        return object_type, [f"json: {exc}"]
    except json.JSONDecodeError as exc:
        return object_type, [f"json: {exc}"]
    if not isinstance(obj, dict):
        return object_type, ["json: top-level value must be an object"]
    if object_type is None:
        try:
            object_type = detect_type(obj)
        except ValueError as exc:
            return None, [str(exc)]
    return object_type, validate_object(obj, object_type)
