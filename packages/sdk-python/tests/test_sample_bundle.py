"""The committed refund-agent sample must verify and print its incidents
with the one documented command (buyer-readiness part 1)."""

import subprocess
import sys

from oathon.validate import find_spec_dir

SAMPLE = find_spec_dir().parent / "samples" / "refund-agent"


def test_sample_bundle_verifies_and_prints_incidents():
    result = subprocess.run(
        [sys.executable, "-m", "oathon.cli", "verify-bundle", str(SAMPLE)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "BUNDLE OK" in out
    assert "AUTHORITY FINDINGS" in out
    assert out.count("OUTSIDE") == 2  # over-limit + denied-then-executed
    assert "lte 20000 violated (observed 75000)" in out
    assert "denied but execution occurred" in out
    assert "1 within" in out  # the clean flow stays clean
