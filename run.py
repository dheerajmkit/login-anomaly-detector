#!/usr/bin/env python3
"""CLI entry point: parse an auth log and report login anomalies."""

import argparse
import json
import sys

from detector import parse
from detector.bruteforce import detect_bruteforce
from detector.spray import detect_spray
from detector.config import DEFAULTS


def main():
    ap = argparse.ArgumentParser(
        description="Detect brute-force and password-spray attacks in auth logs."
    )
    ap.add_argument("logfile", help="auth log file (syslog style or CSV)")
    ap.add_argument("--json", action="store_true", help="emit alerts as JSON")
    args = ap.parse_args()

    events, skipped = parse(args.logfile)
    alerts = detect_bruteforce(events, **DEFAULTS["bruteforce"])
    alerts += detect_spray(events, **DEFAULTS["spray"])
    alerts.sort(key=lambda a: a["window_start"])

    if args.json:
        print(json.dumps({"events": len(events), "alerts": alerts}, indent=2))
        return 0

    print(f"Parsed {len(events)} events ({skipped} skipped). {len(alerts)} alert(s):")
    for a in alerts:
        if a["type"] == "bruteforce":
            print(
                f"  [BRUTEFORCE] user={a['user']} src={a['src_ip']} "
                f"count={a['count']} severity={a['severity']}"
            )
        else:
            print(
                f"  [SPRAY] src={a['src_ip']} users={a['count']} "
                f"severity={a['severity']}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
