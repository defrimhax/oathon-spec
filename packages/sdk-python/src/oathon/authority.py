"""Authority evaluation (SPEC.md §7, AUTH-001..009; INV-017).

Deterministic classification of one operation against its mandate and an
explicitly identified evidence set. Priority: outside > ambiguous > within
(AUTH-007: only fully satisfied supported rules produce within; AUTH-006:
anything non-machine-evaluable degrades to ambiguous, never to within).
"""

from __future__ import annotations

from typing import Any

WITHIN, OUTSIDE, AMBIGUOUS = "within", "outside", "ambiguous"

_SAT, _VIOLATED, _UNKNOWN = "satisfied", "violated", "unknown"


def _compare(op: str, actual: Any, expected: Any) -> str:
    if actual is None:
        return _UNKNOWN  # declared evaluable field absent from action data
    try:
        if op == "eq":
            return _SAT if actual == expected else _VIOLATED
        if op == "neq":
            return _SAT if actual != expected else _VIOLATED
        if op == "in":
            if not isinstance(expected, list):
                return _UNKNOWN
            return _SAT if actual in expected else _VIOLATED
        if op in ("lt", "lte", "gt", "gte"):
            if isinstance(actual, bool) or not isinstance(actual, (int, float)):
                return _UNKNOWN
            if op == "lt":
                return _SAT if actual < expected else _VIOLATED
            if op == "lte":
                return _SAT if actual <= expected else _VIOLATED
            if op == "gt":
                return _SAT if actual > expected else _VIOLATED
            return _SAT if actual >= expected else _VIOLATED
    except TypeError:
        return _UNKNOWN
    return _UNKNOWN  # unsupported operator (MANDATE-013)


def _eval_comparison(comp: dict[str, Any], evaluation_metadata: dict[str, Any]) -> str:
    path = comp.get("path")
    if path not in evaluation_metadata:
        return _UNKNOWN  # not extracted -> not evaluable from evidence
    return _compare(comp.get("op"), evaluation_metadata.get(path), comp.get("value"))


def _count_position(primary: dict[str, Any], all_events: list[dict[str, Any]],
                    action: str) -> tuple[int, bool]:
    """Position of `primary` among the day's executions of `action`,
    ordered by (occurred_at, event_id) (AUTH-008). Returns (position,
    boundary_tied) where boundary_tied means neighbors share occurred_at."""
    day = primary["occurred_at"][:10]
    peers = sorted(
        (e for e in all_events
         if e.get("event_type") == "action_executed"
         and e.get("metadata", {}).get("action") == action
         and e["occurred_at"][:10] == day),
        key=lambda e: (e["occurred_at"], e["event_id"]),
    )
    ids = [e["event_id"] for e in peers]
    pos = ids.index(primary["event_id"]) if primary["event_id"] in ids else len(ids)
    tied = False
    if 0 < pos < len(peers):
        tied = peers[pos - 1]["occurred_at"] == peers[pos]["occurred_at"]
    return pos, tied


def evaluate_operation(
    mandate: dict[str, Any],
    operation_events: list[dict[str, Any]],
    evidence_events: list[dict[str, Any]],
    coverage_complete: bool,
    revocation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify one operation. `operation_events` share an operation_id;
    `evidence_events` is the full identified evidence set (AUTH-009)."""
    reasons: list[str] = []
    verdicts: list[str] = []

    executions = [e for e in operation_events if e.get("event_type") == "action_executed"]
    requests = [e for e in operation_events if e.get("event_type") == "action_requested"]
    primary = executions[0] if executions else (requests[0] if requests else None)
    if primary is None:
        return {"determination": AMBIGUOUS, "action": None,
                "reasons": ["no action event in operation"], "executed": False}

    action = primary.get("metadata", {}).get("action")
    em = primary.get("evaluation_metadata", {}) or {}

    def outside(reason: str) -> None:
        verdicts.append(OUTSIDE)
        reasons.append(reason)

    def ambiguous(reason: str) -> None:
        verdicts.append(AMBIGUOUS)
        reasons.append(reason)

    validity = mandate.get("validity", {})
    at = primary["occurred_at"]
    if at < validity.get("not_before", "") or at >= validity.get("not_after", "~"):
        outside(f"mandate not valid at {at} (validity window)")
    if revocation is not None and revocation.get("revoked_at", "~") <= at:
        outside(f"mandate revoked at {revocation['revoked_at']}, before {at}")

    authority = mandate.get("authority", {})
    if action in authority.get("forbidden_actions", []):
        outside(f"action {action!r} is forbidden (AUTH-001)")
    permitted = {p["action"]: p for p in authority.get("permitted_actions", [])}
    if action not in permitted:
        outside(f"action {action!r} is not a permitted action (AUTH-002)")

    for constraint in authority.get("constraints", []):
        c_action = constraint.get("action")
        if c_action is not None and c_action != action:
            continue
        if constraint.get("op") == "max_count_per_utc_day":
            if not executions:
                continue
            limit = constraint.get("value")
            pos, tied = _count_position(primary, evidence_events, action)
            if pos >= limit:
                if tied:
                    ambiguous(
                        f"daily count boundary for {action!r} is clock-order-dependent (AUTH-008)"
                    )
                else:
                    outside(f"execution #{pos + 1} exceeds max_count_per_utc_day={limit}")
            continue
        verdict = _eval_comparison(constraint, em)
        if verdict == _VIOLATED:
            outside(
                f"constraint {constraint.get('path')} {constraint.get('op')} "
                f"{constraint.get('value')!r} violated (observed "
                f"{em.get(constraint.get('path'))!r}) (AUTH-003)"
            )
        elif verdict == _UNKNOWN:
            ambiguous(
                f"constraint {constraint.get('path')} {constraint.get('op')} not "
                f"machine-evaluable from evidence (AUTH-006)"
            )

    for trigger in authority.get("approval_triggers", []):
        if trigger.get("action") != action or not executions:
            continue
        results = [_eval_comparison(c, em) for c in trigger.get("all", [])]
        if _UNKNOWN in results:
            ambiguous("approval-trigger condition not machine-evaluable (AUTH-006)")
            continue
        if all(r == _SAT for r in results):
            denied = [e for e in operation_events
                      if e.get("event_type") == "approval_denied"]
            granted = [e for e in operation_events
                       if e.get("event_type") == "approval_granted"
                       and e["occurred_at"] <= primary["occurred_at"]]
            if denied:
                outside("required approval was denied but execution occurred (AUTH-005)")
            elif not granted:
                if coverage_complete:
                    outside("required approval absent from evidence (AUTH-005)")
                else:
                    ambiguous(
                        "required approval absent, but evidence-set coverage is "
                        "incomplete (AUTH-009)"
                    )
            else:
                reasons.append(
                    f"required approval granted (event {granted[0]['event_id']})"
                )

    if OUTSIDE in verdicts:
        determination = OUTSIDE
    elif AMBIGUOUS in verdicts:
        determination = AMBIGUOUS
    else:
        determination = WITHIN
        reasons.append("all supported rules fully satisfied (AUTH-007)")
    return {
        "determination": determination,
        "action": action,
        "operation_id": primary.get("operation_id"),
        "occurred_at": primary.get("occurred_at"),
        "executed": bool(executions),
        "reasons": reasons,
        "evidence_refs": [e["event_id"] for e in operation_events],
    }
