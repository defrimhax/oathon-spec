"""Canonicalization and strict-JSON tests (CRYPTO §2–§3, TEST-002)."""

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from oathon.crypto import canonicalize, digest_string, decode_digest_string
from oathon.jsonutil import StrictJSONError, loads_strict


def test_jcs_key_ordering():
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_jcs_unicode_not_escaped():
    # JCS emits literal UTF-8 for non-control characters
    assert canonicalize({"k": "ÅÄÖ"}) == '{"k":"ÅÄÖ"}'.encode()


def test_jcs_number_formatting():
    # RFC 8785 uses ECMAScript number serialization
    assert canonicalize([1.0, 2.5, 1e30]) == b"[1,2.5,1e+30]"


def test_jcs_null_and_bool():
    assert canonicalize({"a": None, "b": True}) == b'{"a":null,"b":true}'


def test_duplicate_keys_rejected():
    with pytest.raises(StrictJSONError, match="duplicate"):
        loads_strict('{"a": 1, "a": 2}')


@pytest.mark.parametrize("text", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_rejected(text):
    with pytest.raises(StrictJSONError):
        loads_strict(f'{{"x": {text}}}')


def test_canonicalize_rejects_nan_value():
    with pytest.raises(StrictJSONError):
        canonicalize({"x": math.nan})


def test_digest_string_roundtrip():
    raw = bytes(range(32))
    assert decode_digest_string(digest_string(raw)) == raw


def test_digest_string_rejects_wrong_length():
    with pytest.raises(Exception):
        digest_string(b"\x00" * 31)


def test_unsafe_integer_rejected():
    # CRYPTO §2: integers outside the safe domain must not canonicalize
    with pytest.raises(Exception):
        canonicalize({"n": 2**53})


json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1)
    | st.floats(allow_nan=False, allow_infinity=False, width=64)
    | st.text(max_size=40),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(max_size=10), children, max_size=4),
    max_leaves=20,
)


@given(json_values)
def test_canonicalization_is_deterministic(value):
    assert canonicalize(value) == canonicalize(value)


@given(st.dictionaries(
    st.text(min_size=1, max_size=8),
    st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),  # CRYPTO §2 safe domain
    min_size=2, max_size=6,
))
def test_canonicalization_key_order_independent(d):
    items = list(d.items())
    reversed_dict = dict(reversed(items))
    assert canonicalize(d) == canonicalize(reversed_dict)
