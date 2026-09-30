"""pytest suite for the login anomaly detector."""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detector.parser import parse_lines
from detector.bruteforce import detect_bruteforce
from detector.spray import detect_spray

BASE = datetime(2026, 9, 28, 10, 0, 0)


def _ev(user, ip, minute, result="failed"):
    return {
        "timestamp": BASE + timedelta(minutes=minute),
        "user": user,
        "src_ip": ip,
        "result": result,
    }


def test_parser_syslog_line():
    line = "Sep 28 10:15:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22"
    events, skipped = parse_lines([line])
    assert skipped == 0
    e = events[0]
    assert e["user"] == "root"
    assert e["src_ip"] == "203.0.113.5"
    assert e["result"] == "failed"


def test_parser_syslog_accepted():
    line = "Sep 28 10:15:01 web-01 sshd[1234]: Accepted password for alice from 10.0.1.20 port 51102"
    events, _ = parse_lines([line])
    assert events[0]["result"] == "success"


def test_parser_csv_rows():
    lines = [
        "timestamp,user,src_ip,result",
        "2026-09-28T10:00:00,alice,10.0.1.20,success",
        "2026-09-28T10:01:00,root,203.0.113.5,failed",
    ]
    events, skipped = parse_lines(lines)
    assert skipped == 0 and len(events) == 2
    assert events[0]["user"] == "alice"
    assert events[1]["result"] == "failed"


def test_bruteforce_fires_on_burst():
    events = [_ev("root", "203.0.113.5", m) for m in range(6)]
    alerts = detect_bruteforce(events, max_attempts=5, window_minutes=10)
    assert len(alerts) == 1
    a = alerts[0]
    assert a["type"] == "bruteforce"
    assert a["user"] == "root" and a["src_ip"] == "203.0.113.5"
    assert a["count"] >= 5


def test_bruteforce_quiet_on_scattered_failures():
    events = [_ev("root", "203.0.113.5", m) for m in (0, 60, 120, 180)]
    alerts = detect_bruteforce(events, max_attempts=5, window_minutes=10)
    assert alerts == []


def test_spray_fires_on_multi_user_pattern():
    users = ["alice", "bob", "carol", "dave", "erin", "frank"]
    events = [_ev(u, "198.51.100.23", m) for m, u in enumerate(users)]
    alerts = detect_spray(events, min_users=5, window_minutes=10)
    assert len(alerts) == 1
    a = alerts[0]
    assert a["type"] == "spray"
    assert a["src_ip"] == "198.51.100.23"
    assert a["count"] >= 5


def test_spray_quiet_on_single_user():
    events = [_ev("alice", "10.0.1.20", m) for m in range(3)]
    alerts = detect_spray(events, min_users=5, window_minutes=10)
    assert alerts == []
