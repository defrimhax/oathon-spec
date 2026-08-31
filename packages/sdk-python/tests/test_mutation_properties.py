"""Property-based mutation tests (TESTING.md §3: any mutation of protected
fields must be detected; TEST-002)."""

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from oathon import crypto
from oathon.crypto import VerificationError
from oathon.verify import verify_chain, verify_event


@pytest.fixture(scope="module")
def chain(vectors_module):
    case = next(c for c in vectors_module["cases"] if c["name"] == "chain-valid")
    return case["events"]


@pytest.fixture(scope="module")
def vectors_module():
    import json as _json

    from oathon.validate import find_spec_dir

    return _json.loads((find_spec_dir() / "vectors" / "v0.1" / "vectors.json").read_text())


def _leaf_paths(obj, prefix=()):
    """All paths to scalar leaves in a JSON structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaf_paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaf_paths(v, prefix + (i,))
    else:
        yield prefix


def _set(obj, path, value):
    out = json.loads(json.dumps(obj))
    target = out
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value
    return out


@settings(max_examples=60, deadline=None)
@given(data=st.data())
def test_any_leaf_mutation_is_detected(vectors_module, data):
    """Mutating any covered scalar leaf of any historical event fails verification."""
    case = next(c for c in vectors_module["cases"] if c["name"] == "chain-valid")
    events = case["events"]
    event_index = data.draw(st.integers(0, len(events) - 1))
    event = events[event_index]
    paths = [p for p in _leaf_paths(event) if p != ("event_hash",)]
    path = data.draw(st.sampled_from(paths))
    mutated_value = data.draw(
        st.text(min_size=1, max_size=8) | st.integers(-10**6, 10**6) | st.booleans()
    )
    mutated_event = _set(event, path, mutated_value)
    if mutated_event == event:
        return  # drew the original value; nothing mutated
    mutated_chain = events[:event_index] + [mutated_event] + events[event_index + 1:]
    with pytest.raises(VerificationError):
        verify_chain(mutated_chain)


@settings(max_examples=30, deadline=None)
@given(bit=st.integers(0, 255))
def test_event_hash_bitflip_detected(vectors_module, bit):
    """Flipping any byte of the stored digest breaks verification."""
    case = next(c for c in vectors_module["cases"] if c["name"] == "event-genesis")
    event = dict(case["object"])
    raw = bytearray(crypto.decode_digest_string(case["expected"]["event_hash"]))
    raw[bit % 32] ^= max(1, bit // 32)
    event["event_hash"] = crypto.digest_string(bytes(raw))
    with pytest.raises(VerificationError):
        verify_event(event)


def test_reordered_chain_detected(vectors_module):
    case = next(c for c in vectors_module["cases"] if c["name"] == "chain-valid")
    events = case["events"]
    with pytest.raises(VerificationError):
        verify_chain([events[1], events[0], events[2]])


def test_gap_in_chain_detected(vectors_module):
    case = next(c for c in vectors_module["cases"] if c["name"] == "chain-valid")
    events = case["events"]
    with pytest.raises(VerificationError):
        verify_chain([events[0], events[2]])


def test_signature_value_mutation_detected(vectors_module, ):
    case = next(c for c in vectors_module["cases"] if c["name"] == "mandate-valid")
    obj = json.loads(json.dumps(case["object"]))
    value = obj["signature"]["value"]
    obj["signature"]["value"] = value[:-1] + ("A" if value[-1] != "A" else "B")
    raw_pub = None
    from oathon.validate import find_spec_dir

    keys = json.loads((find_spec_dir() / "vectors" / "v0.1" / "keys.json").read_text())
    for entry in keys["keys"].values():
        if entry["key_id"] == obj["signature"]["key_id"]:
            raw_pub = crypto.b64u_decode(entry["public_key_b64u"])
    with pytest.raises(VerificationError):
        crypto.verify_object(obj, crypto.DOMAIN_MANDATE, raw_pub)
