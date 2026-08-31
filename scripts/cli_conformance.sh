#!/bin/sh
# Run the INSTALLED `oathon` CLI against the normative vectors.
# Used by CI's wheel-install job and runnable locally:
#   sh scripts/cli_conformance.sh [python-with-oathon-installed]
set -e
PY="${1:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"

"$PY" - "$ROOT" "$WORK" <<'EOF'
import json, sys
from pathlib import Path
root, work = Path(sys.argv[1]), Path(sys.argv[2])
vectors = json.loads((root / "spec/vectors/v0.1/vectors.json").read_text())
keys = json.loads((root / "spec/vectors/v0.1/keys.json").read_text())
by = {c["name"]: c for c in vectors["cases"]}
(work / "mandate.json").write_text(json.dumps(by["mandate-valid"]["object"]))
(work / "mandate-tampered.json").write_text(json.dumps(by["mandate-modified-field"]["object"]))
(work / "chain.json").write_text(json.dumps(by["chain-valid"]["events"]))
seg = by["segment-close-valid"]
(work / "close.json").write_text(json.dumps(seg["close"]))
(work / "events.json").write_text(json.dumps(seg["events"]))
(work / "auth.json").write_text(json.dumps(seg["writer_auth"]))
(work / "keys.json").write_text(json.dumps(
    {e["key_id"]: e["public_key_b64u"] for e in keys["keys"].values()}))
EOF

oathon validate "$WORK/mandate.json"
oathon verify "$WORK/mandate.json" --type mandate --keys "$WORK/keys.json" \
  --at 2026-10-01T00:00:00.000Z
oathon verify "$WORK/chain.json" --chain
oathon verify "$WORK/close.json" --type segment-close --keys "$WORK/keys.json" \
  --events "$WORK/events.json" --writer-auth "$WORK/auth.json"
if oathon verify "$WORK/mandate-tampered.json" --type mandate --keys "$WORK/keys.json"; then
  echo "ERROR: tampered mandate was accepted"; exit 1
else
  echo "TAMPERED MANDATE REJECTED (expected)"
fi
echo "CLI CONFORMANCE OK"
