"""oathon CLI — Phase 1 scope: `validate` (SDK-012) and `verify` (SDK-011)
over static fixtures. Exit code 0 = OK, 1 = validation/verification failure,
2 = usage error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .crypto import VerificationError
from .jsonutil import loads_strict
from .validate import SCHEMA_FILES, validate_text
from .verify import (
    KeySet,
    mandate_status,
    verify_chain,
    verify_segment_close,
    verify_segment_sequence,
    verify_signed,
)


def _load(path: str):
    return loads_strict(Path(path).read_bytes())


def cmd_validate(args: argparse.Namespace) -> int:
    text = Path(args.file).read_bytes()
    object_type, errors = validate_text(text, args.type)
    label = object_type or "unknown"
    if errors:
        print(f"INVALID ({label}): {args.file}")
        for err in errors:
            print(f"  - {err}")
        return 1
    print(f"VALID ({label}): {args.file}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        if args.spool:
            from .spool import verify_spool

            keyset = KeySet.from_json(_load(args.keys)) if args.keys else None
            writer_auth = _load(args.writer_auth) if args.writer_auth else None
            summary = verify_spool(args.file, writer_auth, keyset)
            sig_note = "signatures verified" if summary["close_signatures_verified"] \
                else "chains only (pass --keys and --writer-auth for signatures)"
            print(
                f"SPOOL OK: {summary['closed_segments']} closed segment(s) "
                f"({summary['closed_events']} events), open: {summary['open_segments']}; {sig_note}"
            )
            return 0

        if args.chain:
            events = _load(args.file)
            if not isinstance(events, list):
                print("verify --chain expects a JSON array of events")
                return 2
            verify_chain(events)
            print(f"CHAIN OK: {len(events)} event(s), hashes and links verified")
            return 0

        if args.segment_chain:
            closes = _load(args.file)
            if not isinstance(closes, list):
                print("verify --segment-chain expects a JSON array of segment-close records")
                return 2
            verify_segment_sequence(closes)
            print(f"SEGMENT CHAIN OK: {len(closes)} segment-close record(s) linked")
            return 0

        obj = _load(args.file)
        if args.type == "segment-close" and args.events:
            if not (args.keys and args.writer_auth):
                print("segment-close verification needs --keys and --writer-auth")
                return 2
            keyset = KeySet.from_json(_load(args.keys))
            writer_auth = _load(args.writer_auth)
            events = _load(args.events)
            verify_segment_close(obj, events, writer_auth, keyset)
            print("SEGMENT OK: signature, writer authorization, and chain verified")
            return 0

        if not args.keys:
            print("verify needs --keys (key_id -> base64url public key)")
            return 2
        keyset = KeySet.from_json(_load(args.keys))
        verify_signed(obj, args.type, keyset)
        extra = ""
        if args.type == "mandate" and args.at:
            extra = f" (status at {args.at}: {mandate_status(obj, args.at)})"
        print(f"SIGNATURE OK ({args.type}): {args.file}{extra}")
        return 0
    except VerificationError as exc:
        print(f"VERIFICATION FAILED: {exc}")
        return 1


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    from .bundle import BundleError, verify_bundle

    try:
        summary = verify_bundle(args.directory)
    except BundleError as exc:
        print(f"BUNDLE VERIFICATION FAILED: {exc}")
        return 1
    print(f"BUNDLE OK: {summary['artifacts_verified']} artifacts, "
          f"{summary['events']} events in {summary['segments']} segment(s), "
          f"{summary['closes_verified']} close(s) verified, "
          f"{summary['anchors_verified']} anchor(s) verified")
    if summary["unanchored_segments"]:
        print(f"  disclosed: unanchored segments: {summary['unanchored_segments']}")
    if summary["key_continuity_breaks"]:
        print(f"  disclosed: key continuity breaks: {len(summary['key_continuity_breaks'])}")
    if summary["closes_unverified"] or summary["partial_writer_chains"]:
        print(f"  disclosed: unverified closes {summary['closes_unverified']}, "
              f"partial writer chains {summary['partial_writer_chains']}")
    _print_authority_findings(Path(args.directory), summary)
    return 0


def _print_authority_findings(bundle: Path, summary) -> None:
    """Classify the bundle's operations per SPEC.md §7 (public protocol
    semantics) and print outside/ambiguous findings. Integrity and authority
    are separate verdicts: incidents do not change the exit code."""
    from .authority import evaluate_operation

    try:
        mandates = {m["mandate_id"]: m
                    for m in loads_strict((bundle / "mandates.json").read_bytes())}
        revocations = {r["mandate_id"]: r
                       for r in loads_strict((bundle / "revocations.json").read_bytes())}
        events = [loads_strict(line) for line in
                  (bundle / "events.jsonl").read_bytes().split(b"\n") if line]
    except (OSError, ValueError):
        return
    operations: dict[str, list] = {}
    for event in events:
        if event.get("operation_id"):
            operations.setdefault(event["operation_id"], []).append(event)
    if not operations:
        return
    # Evidence-set coverage for AUTH-009: structurally complete when every
    # close verified and writer chains are whole (anchoring not required).
    coverage_complete = not summary["closes_unverified"] and \
        not summary["partial_writer_chains"]
    results = []
    for op_id, op_events in sorted(operations.items()):
        op_events.sort(key=lambda e: (e["occurred_at"], e["event_id"]))
        mandate_id = next((e.get("mandate_id") for e in op_events
                           if e.get("mandate_id")), None)
        mandate = mandates.get(mandate_id)
        if mandate is None:
            continue
        results.append(evaluate_operation(
            mandate, op_events, events, coverage_complete,
            revocation=revocations.get(mandate_id)))
    if not results:
        return
    outside = [r for r in results if r["determination"] == "outside"]
    ambiguous = [r for r in results if r["determination"] == "ambiguous"]
    print("AUTHORITY FINDINGS (SPEC.md §7, evaluated over this bundle):")
    for finding in outside:
        print(f"  OUTSIDE   {finding['action']} · operation {finding['operation_id']}")
        for reason in finding["reasons"]:
            print(f"            - {reason}")
    for finding in ambiguous:
        print(f"  AMBIGUOUS {finding['action']} · operation {finding['operation_id']}: "
              f"{'; '.join(finding['reasons'])}")
    within = len(results) - len(outside) - len(ambiguous)
    print(f"  {len(outside)} outside · {len(ambiguous)} ambiguous · {within} within "
          f"({len(results)} operations)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oathon")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="validate an object against the v0.1 schemas")
    p_validate.add_argument("file")
    p_validate.add_argument("--type", choices=sorted(SCHEMA_FILES), default=None)
    p_validate.set_defaults(func=cmd_validate)

    p_verify = sub.add_parser("verify", help="verify signatures/chains in static fixtures")
    p_verify.add_argument("file")
    p_verify.add_argument("--type", choices=sorted(SCHEMA_FILES), default="mandate")
    p_verify.add_argument("--keys", help="JSON file: key_id -> base64url public key")
    p_verify.add_argument("--chain", action="store_true", help="file is a JSON array of events")
    p_verify.add_argument(
        "--segment-chain", action="store_true",
        help="file is a JSON array of one writer's segment-close records",
    )
    p_verify.add_argument(
        "--spool", action="store_true",
        help="file is a spool directory; verify all segments offline",
    )
    p_verify.add_argument("--events", help="events array for segment-close verification")
    p_verify.add_argument("--writer-auth", help="writer-authorization record file")
    p_verify.add_argument("--at", help="protocol timestamp for mandate status reporting")
    p_verify.set_defaults(func=cmd_verify)

    p_bundle = sub.add_parser("verify-bundle",
                              help="independently verify an evidence bundle (BUNDLE-004)")
    p_bundle.add_argument("directory")
    p_bundle.set_defaults(func=cmd_verify_bundle)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
