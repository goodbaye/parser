"""Command-line interface for LogSentinel."""

from __future__ import annotations

import argparse
import sys

from .parser import parse_file
from .detectors import run_all_detectors
from .report import print_console_report, write_json_report, write_csv_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentinel",
        description="Analyze Linux SSH auth logs for brute-force and suspicious login activity.",
    )
    p.add_argument("logfile", help="Path to an auth.log / secure file to analyze")
    p.add_argument("--year", type=int, default=None,
                    help="Year to assume for log timestamps (syslog lines have no year). "
                         "Defaults to the current year.")
    p.add_argument("--json", metavar="PATH", help="Write findings as JSON to PATH")
    p.add_argument("--csv", metavar="PATH", help="Write findings as CSV to PATH")
    p.add_argument("--quiet", action="store_true", help="Suppress the console report")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        events = list(parse_file(args.logfile, year=args.year))
    except FileNotFoundError:
        print(f"Error: log file not found: {args.logfile}", file=sys.stderr)
        return 1

    findings = run_all_detectors(events)

    if not args.quiet:
        print(f"Parsed {len(events)} recognized log lines from {args.logfile}\n")
        print_console_report(findings)

    if args.json:
        write_json_report(findings, args.json)
        print(f"JSON report written to {args.json}")

    if args.csv:
        write_csv_report(findings, args.csv)
        print(f"CSV report written to {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
