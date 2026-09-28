"""Parse authentication logs into normalized event dicts.

Supported formats:
  * syslog-style sshd lines, e.g.
    "Sep 28 10:15:01 host sshd[1234]: Failed password for root from 203.0.113.5 port 22"
  * CSV rows with header "timestamp,user,src_ip,result"

Each event is a dict: {"timestamp": datetime, "user": str, "src_ip": str,
"result": "failed" | "success"}.
"""

import csv
import re
from datetime import datetime

SYSLOG_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+(?P<proc>[\w.\-]+)(?:\[\d+\])?:\s+"
    r"(?P<result>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)

CSV_HEADER = "timestamp,user,src_ip,result"

FAILED_WORDS = {"failed", "fail", "failure", "denied"}
SUCCESS_WORDS = {"accepted", "success", "succeeded", "ok"}


def _syslog_ts(mon, day, time_):
    return datetime.strptime(
        f"{mon} {day} {datetime.now().year} {time_}", "%b %d %Y %H:%M:%S"
    )


def _csv_ts(text):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            ts = datetime.strptime(text.strip(), fmt)
            return ts.replace(year=datetime.now().year) if ts.year == 1900 else ts
        except ValueError:
            continue
    raise ValueError(f"unparseable timestamp: {text!r}")


def _norm_result(text):
    word = text.strip().lower()
    if word in FAILED_WORDS:
        return "failed"
    if word in SUCCESS_WORDS:
        return "success"
    return word


def parse_lines(lines):
    """Parse an iterable of log lines. Returns (events, skipped_count)."""
    lines = [ln.strip() for ln in lines if ln.strip()]
    if not lines:
        return [], 0
    events, skipped = [], 0
    if lines[0].lower() == CSV_HEADER:
        for row in csv.reader(lines[1:]):
            if len(row) != 4:
                skipped += 1
                continue
            ts_text, user, src_ip, result = row
            try:
                events.append(
                    {
                        "timestamp": _csv_ts(ts_text),
                        "user": user.strip(),
                        "src_ip": src_ip.strip(),
                        "result": _norm_result(result),
                    }
                )
            except ValueError:
                skipped += 1
        return events, skipped
    for line in lines:
        m = SYSLOG_RE.match(line)
        if not m:
            skipped += 1
            continue
        try:
            events.append(
                {
                    "timestamp": _syslog_ts(m["mon"], m["day"], m["time"]),
                    "user": m["user"],
                    "src_ip": m["ip"],
                    "result": _norm_result(m["result"]),
                }
            )
        except ValueError:
            skipped += 1
    return events, skipped


def parse(path):
    """Parse a log file. Returns (events, skipped_count)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh)
