"""Unit tests for the authority evaluator (AUTH-001..009) on synthetic
events — edge cases beyond the report-engine scenarios."""

from oathon.authority import evaluate_operation

MANDATE = {
    "mandate_id": "m1",
    "validity": {"not_before": "2026-09-01T00:00:00.000Z",
                 "not_after": "2026-12-01T00:00:00.000Z"},
    "authority": {
        "permitted_actions": [
            {"action": "issue_refund", "evaluable_fields": ["/amount/minor_units"]}],
        "forbidden_actions": ["delete_customer_account"],
        "constraints": [
            {"action": "issue_refund", "path": "/amount/minor_units", "op": "lte", "value": 20000},
            {"action": "issue_refund", "op": "max_count_per_utc_day", "value": 2},
        ],
        "approval_triggers": [
            {"action": "issue_refund",
             "all": [{"path": "/amount/minor_units", "op": "gt", "value": 10000}]}],
    },
}


def ev(event_id, event_type, occurred_at, amount=5000, action="issue_refund", op="op1"):
    return {
        "event_id": event_id, "event_type": event_type, "occurred_at": occurred_at,
        "operation_id": op, "metadata": {"action": action},
        "evaluation_metadata": {"/amount/minor_units": amount},
    }


def run(op_events, all_events=None, complete=True, revocation=None):
    return evaluate_operation(MANDATE, op_events, all_events or op_events,
                              complete, revocation)


def test_within():
    events = [ev("e1", "action_requested", "2026-09-05T10:00:00.000Z"),
              ev("e2", "action_executed", "2026-09-05T10:00:01.000Z")]
    assert run(events)["determination"] == "within"


def test_denied_approval_outside():
    events = [
        ev("e1", "action_requested", "2026-09-05T10:00:00.000Z", amount=15000),
        {"event_id": "e2", "event_type": "approval_denied",
         "occurred_at": "2026-09-05T10:01:00.000Z", "operation_id": "op1",
         "metadata": {"action": "issue_refund"}},
        ev("e3", "action_executed", "2026-09-05T10:02:00.000Z", amount=15000),
    ]
    result = run(events)
    assert result["determination"] == "outside"
    assert any("denied" in r for r in result["reasons"])


def test_absent_approval_complete_coverage_outside():
    events = [ev("e1", "action_executed", "2026-09-05T10:00:00.000Z", amount=15000)]
    assert run(events, complete=True)["determination"] == "outside"


def test_absent_approval_incomplete_coverage_ambiguous():
    events = [ev("e1", "action_executed", "2026-09-05T10:00:00.000Z", amount=15000)]
    result = run(events, complete=False)
    assert result["determination"] == "ambiguous"  # AUTH-009
    assert any("coverage" in r for r in result["reasons"])


def test_daily_count_limit_exceeded():
    day_events = [
        ev(f"x{i}", "action_executed", f"2026-09-05T0{i}:00:00.000Z", op=f"op{i}")
        for i in range(1, 4)
    ]
    result = evaluate_operation(MANDATE, [day_events[2]], day_events, True)
    assert result["determination"] == "outside"
    assert any("max_count_per_utc_day" in r for r in result["reasons"])
    # The first two executions stay within the limit:
    assert evaluate_operation(MANDATE, [day_events[0]], day_events, True)[
        "determination"] == "within"


def test_daily_count_boundary_tie_is_ambiguous():
    """AUTH-008: clock-order-dependent boundary position degrades to ambiguous."""
    same_time = "2026-09-05T08:00:00.000Z"
    day_events = [
        ev("a1", "action_executed", "2026-09-05T07:00:00.000Z", op="opA"),
        ev("a2", "action_executed", same_time, op="opB"),
        ev("a3", "action_executed", same_time, op="opC"),
    ]
    boundary = max(day_events[1:], key=lambda e: e["event_id"])
    result = evaluate_operation(MANDATE, [boundary], day_events, True)
    assert result["determination"] == "ambiguous"


def test_revoked_mandate_outside():
    events = [ev("e1", "action_executed", "2026-09-20T10:00:00.000Z")]
    revocation = {"revoked_at": "2026-09-10T00:00:00.000Z"}
    result = run(events, revocation=revocation)
    assert result["determination"] == "outside"
    assert any("revoked" in r for r in result["reasons"])


def test_expired_and_not_yet_valid_outside():
    late = [ev("e1", "action_executed", "2026-12-01T00:00:00.000Z")]
    early = [ev("e2", "action_executed", "2026-08-31T00:00:00.000Z")]
    assert run(late)["determination"] == "outside"
    assert run(early)["determination"] == "outside"


def test_unknown_operator_is_ambiguous_never_satisfied():
    """MANDATE-013: unsupported constraints never silently satisfied."""
    mandate = {**MANDATE, "authority": {
        **MANDATE["authority"],
        "constraints": [{"action": "issue_refund", "path": "/amount/minor_units",
                         "op": "matches_regex", "value": ".*"}],
        "approval_triggers": [],
    }}
    events = [ev("e1", "action_executed", "2026-09-05T10:00:00.000Z")]
    result = evaluate_operation(mandate, events, events, True)
    assert result["determination"] == "ambiguous"


def test_forbidden_beats_ambiguous():
    events = [ev("e1", "action_executed", "2026-09-05T10:00:00.000Z",
                 action="delete_customer_account", amount=None)]
    assert run(events)["determination"] == "outside"
