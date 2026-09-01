"""DX-002 literal quickstart executor.

Parses docs/quickstart.md and executes ONLY the commands the document
states, in order: each ```bash block runs via sh in the audit work
directory (with .venv/bin on PATH once it exists); ```python blocks are
executed cumulatively (the document presents them as one Python session).
Wall-clock time per step is recorded. Any failure, undefined name, or
missing file the doc assumed is a friction finding.

Usage: python3 scripts/quickstart_audit.py [quickstart.md] [workdir]
"""

import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    doc = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "docs/quickstart.md")
    work = Path(sys.argv[2] if len(sys.argv) > 2 else ROOT / ".quickstart-audit")
    work.mkdir(parents=True, exist_ok=True)

    blocks = re.findall(r"```(bash|python)\n(.*?)```", doc.read_text(), re.S)
    cumulative_py: list[str] = []
    rows = []
    failed = False
    t_total = time.monotonic()

    for i, (lang, code) in enumerate(blocks, 1):
        label = code.strip().splitlines()[0][:60]
        t0 = time.monotonic()
        if lang == "bash":
            # Hermetic: only the audit workdir's own venv plus system paths.
            # (Run 1 leaked the repo's development venv here, which masked a
            # failure — recorded as audit-tooling friction finding F5.)
            env_path = f"{work / '.venv' / 'bin'}:/usr/bin:/bin:/usr/local/bin"
            proc = subprocess.run(
                ["sh", "-c", code], cwd=work, capture_output=True, text=True,
                env={"PATH": env_path, "HOME": str(Path.home())},
            )
        else:
            cumulative_py.append(code)
            python = work / ".venv" / "bin" / "python"
            if not python.exists():
                python = "python3"
            proc = subprocess.run(
                [str(python), "-c", "\n".join(cumulative_py)],
                cwd=work, capture_output=True, text=True,
            )
        dt = time.monotonic() - t0
        ok = proc.returncode == 0
        failed = failed or not ok
        detail = "" if ok else (proc.stderr.strip() or proc.stdout.strip()).splitlines()[-1][:100]
        rows.append((i, lang, label, dt, "OK" if ok else "FAIL", detail))
        status = "OK  " if ok else "FAIL"
        print(f"step {i:2d} [{lang:6s}] {dt:7.1f}s {status} {label}")
        if not ok:
            print(f"         → {detail}")

    total = time.monotonic() - t_total
    print(f"\nTOTAL: {total:.1f}s ({total / 60:.1f} min; DX-001 budget 30 min) — "
          f"{'ALL STEPS PASSED' if not failed else 'FRICTION FOUND'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
