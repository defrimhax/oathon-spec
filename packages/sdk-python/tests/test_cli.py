"""CLI end-to-end tests (SDK-011/012, TEST-008): real subprocess invocations
against the committed vectors."""

import json
import subprocess
import sys

import pytest

from oathon.validate import find_spec_dir

VDIR = find_spec_dir() / "vectors" / "v0.1"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "oathon.cli", *args],
        capture_output=True, text=True,
    )


@pytest.fixture(scope="module")
def workdir(tmp_path_factory):
    """Materialize vector objects as individual fixture files."""
    d = tmp_path_factory.mktemp("fixtures")
    vectors = json.loads((VDIR / "vectors.json").read_text())
    keys = json.loads((VDIR / "keys.json").read_text())
    by_name = {c["name"]: c for c in vectors["cases"]}

    (d / "keys.json").write_text(json.dumps(
        {k["key_id"]: k["public_key_b64u"] for k in keys["keys"].values()}
    ))
    (d / "mandate.json").write_text(json.dumps(by_name["mandate-valid"]["object"]))
    (d / "mandate-tampered.json").write_text(
        json.dumps(by_name["mandate-modified-field"]["object"])
    )
    (d / "chain.json").write_text(json.dumps(by_name["chain-valid"]["events"]))
    (d / "chain-broken.json").write_text(
        json.dumps(by_name["chain-predecessor-mutation"]["events"])
    )
    seg = by_name["segment-close-valid"]
    (d / "segment-close.json").write_text(json.dumps(seg["close"]))
    (d / "segment-events.json").write_text(json.dumps(seg["events"]))
    (d / "writer-auth.json").write_text(json.dumps(seg["writer_auth"]))
    (d / "segment-chain.json").write_text(
        json.dumps(by_name["segment-chain-valid"]["closes"])
    )
    return d


def test_validate_valid_mandate(workdir):
    r = run_cli("validate", str(workdir / "mandate.json"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "VALID (mandate)" in r.stdout


def test_validate_rejects_placeholder_example(repo_root):
    r = run_cli("validate", str(repo_root / "spec/examples/mandate.example.json"))
    assert r.returncode == 1


def test_verify_valid_mandate(workdir):
    r = run_cli("verify", str(workdir / "mandate.json"), "--type", "mandate",
                "--keys", str(workdir / "keys.json"),
                "--at", "2026-10-01T00:00:00.000Z")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SIGNATURE OK" in r.stdout and "active" in r.stdout


def test_verify_tampered_mandate_fails(workdir):
    r = run_cli("verify", str(workdir / "mandate-tampered.json"), "--type", "mandate",
                "--keys", str(workdir / "keys.json"))
    assert r.returncode == 1
    assert "VERIFICATION FAILED" in r.stdout


def test_verify_chain(workdir):
    r = run_cli("verify", str(workdir / "chain.json"), "--chain")
    assert r.returncode == 0 and "CHAIN OK" in r.stdout


def test_verify_broken_chain_fails(workdir):
    r = run_cli("verify", str(workdir / "chain-broken.json"), "--chain")
    assert r.returncode == 1


def test_verify_segment_close_end_to_end(workdir):
    r = run_cli("verify", str(workdir / "segment-close.json"), "--type", "segment-close",
                "--keys", str(workdir / "keys.json"),
                "--events", str(workdir / "segment-events.json"),
                "--writer-auth", str(workdir / "writer-auth.json"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SEGMENT OK" in r.stdout


def test_verify_segment_chain(workdir):
    r = run_cli("verify", str(workdir / "segment-chain.json"), "--segment-chain")
    assert r.returncode == 0 and "SEGMENT CHAIN OK" in r.stdout


def test_verify_spool_cli(tmp_path):
    from oathon.spool import EvidenceWriter

    writer = EvidenceWriter(tmp_path / "spool", "org_nordwind_test", "support-refund")
    writer.append(writer.build_event(event_type="error", metadata={"error_class": "x"}))
    writer.close_segment()
    r = run_cli("verify", str(tmp_path / "spool"), "--spool")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SPOOL OK: 1 closed segment(s)" in r.stdout
