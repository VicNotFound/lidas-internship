"""LIDAS command-line interface.

Usage:
  python -m lidas.cli scan  path/to/logfile.log
  python -m lidas.cli tail  path/to/logfile.log   # like `tail -f`
  python -m lidas.cli verify path/to/audit.log

Configuration via environment variables (12-factor app style):
  LIDAS_AUDIT_LOG_PATH  default: ./data/audit.log
  LIDAS_KEY_PATH        default: ./data/hmac.key
  LIDAS_MIN_CONFIDENCE  default: 0.5

Environment variable configuration makes LIDAS trivially configurable in
Docker Compose without rebuilding the image.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from .audit_log import AuditLogVerifier, AuditLogWriter, load_or_create_key
from .emitter import AuditLogEmitter, ConsoleEmitter, MultiEmitter
from .parser import parse_line
from .rules import CONFIDENCE_THRESHOLD_DEFAULT, RuleEngine


def _build_engine() -> RuleEngine:
    raw = os.environ.get("LIDAS_MIN_CONFIDENCE", str(CONFIDENCE_THRESHOLD_DEFAULT))
    try:
        min_confidence = float(raw)
    except ValueError:
        min_confidence = CONFIDENCE_THRESHOLD_DEFAULT
    return RuleEngine(min_confidence=min_confidence)


def _build_emitter() -> tuple[MultiEmitter, AuditLogWriter]:
    audit_path = Path(os.environ.get("LIDAS_AUDIT_LOG_PATH", "./data/audit.log"))
    key_path = Path(os.environ.get("LIDAS_KEY_PATH", "./data/hmac.key"))
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = load_or_create_key(key_path)
    writer = AuditLogWriter(audit_path, key)
    emitter = MultiEmitter(
        [ConsoleEmitter(), AuditLogEmitter(writer)]
    )
    return emitter, writer


def cmd_scan(args: argparse.Namespace) -> int:
    engine = _build_engine()
    emitter, _ = _build_emitter()
    path = Path(args.logfile)
    lines_processed = 0
    alerts_raised = 0

    # errors='replace' substitutes the Unicode replacement character U+FFFD
    # for bytes that cannot be decoded. This prevents a file with binary
    # content or a different encoding from crashing the scan.
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            lines_processed += 1
            event = parse_line(line)
            alerts = engine.process_event(event)
            for alert in alerts:
                emitter.emit(alert)
                alerts_raised += 1

    print(
        f"Processed {lines_processed} lines, raised {alerts_raised} alerts.",
        file=sys.stderr,
    )
    return 0


def cmd_tail(args: argparse.Namespace) -> int:
    engine = _build_engine()
    emitter, _ = _build_emitter()
    path = Path(args.logfile)

    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                event = parse_line(line)
                for alert in engine.process_event(event):
                    emitter.emit(alert)
        except KeyboardInterrupt:
            print("\nStopped.", file=sys.stderr)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    key_path = Path(os.environ.get("LIDAS_KEY_PATH", "./data/hmac.key"))
    key = load_or_create_key(key_path)
    verifier = AuditLogVerifier(key)
    ok, bad_line = verifier.verify(args.auditlog)
    if ok:
        print("OK: audit log chain is intact")
        return 0
    # Returning exit code 1 on tamper makes this usable in shell scripts
    # and CI pipelines: `lidas verify audit.log || alert_ops`
    print(
        f"TAMPER DETECTED: chain broken at line {bad_line}",
        file=sys.stderr,
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lidas",
        description="Lightweight Intrusion Detection System",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Process a log file once and exit")
    scan_p.add_argument("logfile")
    scan_p.set_defaults(func=cmd_scan)

    tail_p = sub.add_parser(
        "tail", help="Follow a growing log file continuously (like tail -f)"
    )
    tail_p.add_argument("logfile")
    tail_p.set_defaults(func=cmd_tail)

    verify_p = sub.add_parser(
        "verify", help="Verify the HMAC chain integrity of an audit log"
    )
    verify_p.add_argument("auditlog")
    verify_p.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
