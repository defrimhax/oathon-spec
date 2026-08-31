"""Schema validation cases from the committed schema-cases.json (Phase 1
requires ≥30 mandate/schema vectors)."""

from oathon.validate import validate_text


def test_case_count(schema_cases):
    assert len(schema_cases["cases"]) >= 30


def test_all_schema_cases(schema_cases):
    failures = []
    for case in schema_cases["cases"]:
        _, errors = validate_text(case["raw"], case["type"])
        actually_valid = not errors
        if actually_valid != case["expected_valid"]:
            failures.append(f"{case['name']}: expected_valid={case['expected_valid']}, errors={errors}")
    assert not failures, "\n".join(failures)


def test_type_autodetection(schema_cases):
    valid = next(c for c in schema_cases["cases"] if c["name"] == "mandate-valid")
    detected, errors = validate_text(valid["raw"], None)
    assert detected == "mandate" and not errors
