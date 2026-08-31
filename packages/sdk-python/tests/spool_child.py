"""Child process for the process-kill adversarial test: appends events in a
tight loop until killed. Usage: python spool_child.py <spool_dir>"""

import sys

from oathon.spool import EvidenceWriter

def main() -> None:
    writer = EvidenceWriter(sys.argv[1], "org_nordwind_test", "support-refund")
    n = 0
    while True:
        writer.append(writer.build_event(
            event_type="error",
            metadata={"error_class": f"loop_{n}"},
        ))
        n += 1
        print(n, flush=True)


if __name__ == "__main__":
    main()
