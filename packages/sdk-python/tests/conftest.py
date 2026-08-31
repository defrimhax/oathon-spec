import json
from pathlib import Path

import pytest

from oathon.validate import find_spec_dir

VECTOR_DIR = find_spec_dir() / "vectors" / "v0.1"


@pytest.fixture(scope="session")
def vectors():
    return json.loads((VECTOR_DIR / "vectors.json").read_text())


@pytest.fixture(scope="session")
def schema_cases():
    return json.loads((VECTOR_DIR / "schema-cases.json").read_text())


@pytest.fixture(scope="session")
def test_keys():
    return json.loads((VECTOR_DIR / "keys.json").read_text())


@pytest.fixture(scope="session")
def keyset(test_keys):
    from oathon.verify import KeySet

    return KeySet.from_json(
        {k["key_id"]: k["public_key_b64u"] for k in test_keys["keys"].values()}
    )


@pytest.fixture(scope="session")
def repo_root():
    return Path(find_spec_dir()).parent
