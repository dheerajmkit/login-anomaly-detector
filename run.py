#!/usr/bin/env python3
"""CLI entry point: parse an auth log and print a summary of events."""

import argparse
import sys

from detector import parse


def main():
    ap = argparse.ArgumentParser(description="Parse auth logs into login events.")
    ap.add_argument("logfile", help="auth log file (syslog style or CSV)")
    args = ap.parse_args()

    events, skipped = parse(args.logfile)
    failed = sum(1 for e in events if e["result"] == "failed")
    print(
        f"Parsed {len(events)} events ({skipped} skipped): "
        f"{failed} failed, {len(events) - failed} successful."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
