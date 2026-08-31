"""Mandate status and semantic-rule tests (Phase 1: expired mandate, future
validity, wrong key handled in vectors; here: time-window semantics)."""

from oathon.verify import mandate_status


def _mandate(vectors):
    return next(c for c in vectors["cases"] if c["name"] == "mandate-valid")["object"]


def test_active_within_window(vectors):
    assert mandate_status(_mandate(vectors), "2026-10-01T12:00:00.000Z") == "active"


def test_future_validity(vectors):
    assert mandate_status(_mandate(vectors), "2026-08-31T23:59:59.999Z") == "not_yet_valid"


def test_expired(vectors):
    assert mandate_status(_mandate(vectors), "2026-12-01T00:00:00.000Z") == "expired"


def test_boundary_not_before_is_inclusive(vectors):
    assert mandate_status(_mandate(vectors), "2026-09-01T00:00:00.000Z") == "active"
